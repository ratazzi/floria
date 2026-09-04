# frozen_string_literal: true

require "json"
require "fileutils"
require "open3"
require "tmpdir"

module Floria
  module Release
    extend self

    ROOT = File.expand_path("..", __dir__)
    APP_NAME = "Floria"
    DMG_VOLUME_NAME = "Floria Installer"
    PRODUCT_NAME = "floria-menubar"
    BUNDLE_ID = "floria.hola.ac"
    CONTAINER_ID = "iCloud.floria.hola.ac"
    MACFUSE_TEAM_ID = "3T5GSNBU6W"
    APP_BUNDLE = File.join(ROOT, "app/.build/Floria.app")

    def run!(*command, env: {}, stdin_data: nil, **options)
      if stdin_data
        _, error, status = Open3.capture3(env, *command, stdin_data:, chdir: ROOT)
        raise "#{command.first} failed: #{error}" unless status.success?
      elsif !system(env, *command, chdir: ROOT, **options)
        raise "command failed: #{command.first}"
      end
    end

    def capture!(*command, env: {}, stdin_data: nil)
      output, error, status = Open3.capture3(env, *command, stdin_data:, chdir: ROOT)
      raise "#{command.first} failed: #{error}" unless status.success?

      output
    end

    def capture_combined!(*command, env: {})
      output, status = Open3.capture2e(env, *command, chdir: ROOT)
      raise "#{command.first} failed: #{output}" unless status.success?

      output
    end

    def build_app
      version = File.read(File.join(ROOT, "Cargo.toml"))[/^version = "([^"]+)"$/, 1]
      build = ENV.fetch("BUILD_NUMBER", Time.now.strftime("%Y%m%d%H%M"))
      identity = ENV.fetch("SIGN_IDENTITY", "-")
      team = ENV.fetch("FLORIA_SIGNING_TEAM_ID", "")
      profile = ENV.fetch("FLORIA_APP_PROVISIONING_PROFILE", "")
      signed_entitlements = File.join(ROOT, "app/.build/Floria.signed.entitlements")
      codesign = ["codesign", "--force", "--sign", identity, "--options", "runtime"]
      codesign << "--timestamp" unless identity == "-"

      puts "==> Building #{APP_NAME}.app v#{version} (build #{build})"
      if !profile.empty?
        raise "FLORIA_APP_PROVISIONING_PROFILE requires a non-ad-hoc SIGN_IDENTITY" if identity == "-"
        raise "Provisioning profile does not exist: #{profile}" unless File.file?(profile)

        verify_signing(profile:)
        FileUtils.mkdir_p(File.dirname(signed_entitlements))
        FileUtils.cp(File.join(ROOT, "app/Floria.entitlements"), signed_entitlements)
        run!("/usr/libexec/PlistBuddy", "-c", "Add :com.apple.application-identifier string #{team}.#{BUNDLE_ID}", signed_entitlements)
        run!("/usr/libexec/PlistBuddy", "-c", "Add :com.apple.developer.team-identifier string #{team}", signed_entitlements)
      elsif identity == "-"
        puts "==> CloudKit disabled in this ad-hoc development build"
      else
        puts "==> CloudKit disabled: set FLORIA_APP_PROVISIONING_PROFILE for a CloudKit-capable signed app"
      end

      puts "==> Building Rust daemon"
      if identity == "-"
        run!("cargo", "build", "--release", "-p", "floria", env: { "FLORIA_SIGNING_TEAM_ID" => nil, "FLORIA_INSECURE_DEVELOPMENT_BUILD" => "1" })
      else
        raise "A signed build requires FLORIA_SIGNING_TEAM_ID" unless team.match?(/\A[A-Z0-9]{10}\z/)

        run!("cargo", "build", "--release", "-p", "floria", env: { "FLORIA_SIGNING_TEAM_ID" => team })
      end

      puts "==> Building Swift app"
      run!("swift", "build", "--package-path", "app", "--configuration", "release", "--product", PRODUCT_NAME)
      bin = capture!("swift", "build", "--package-path", "app", "--configuration", "release", "--show-bin-path").strip

      puts "==> Packaging #{APP_BUNDLE}"
      FileUtils.rm_rf(APP_BUNDLE)
      FileUtils.mkdir_p([File.join(APP_BUNDLE, "Contents/MacOS"), File.join(APP_BUNDLE, "Contents/Resources")])
      {
        File.join(bin, PRODUCT_NAME) => "Contents/MacOS/#{APP_NAME}",
        "target/release/floria" => "Contents/Resources/floria",
        "floria.toml" => "Contents/Resources/floria.toml",
        "app/Assets/AppIcon.icns" => "Contents/Resources/AppIcon.icns",
        "app/Assets/MenuBarTemplate.png" => "Contents/Resources/MenuBarTemplate.png",
        "app/Info.plist" => "Contents/Info.plist"
      }.each { |source, destination| FileUtils.cp(File.expand_path(source, ROOT), File.join(APP_BUNDLE, destination)) }
      FileUtils.cp(profile, File.join(APP_BUNDLE, "Contents/embedded.provisionprofile")) unless profile.empty?
      plist = File.join(APP_BUNDLE, "Contents/Info.plist")
      run!("plutil", "-replace", "CFBundleShortVersionString", "-string", version, plist)
      run!("plutil", "-replace", "CFBundleVersion", "-string", build, plist)
      run!("plutil", "-replace", "FloriaCloudKitEnabled", "-bool", "true", plist) unless profile.empty?
      FileUtils.chmod(0o755, [File.join(APP_BUNDLE, "Contents/MacOS/#{APP_NAME}"), File.join(APP_BUNDLE, "Contents/Resources/floria")])

      daemon = File.join(APP_BUNDLE, "Contents/Resources/floria")
      executable = File.join(APP_BUNDLE, "Contents/MacOS/#{APP_NAME}")
      library_constraint = "app/FloriaDaemonLibraryConstraint.plist"
      verify_library_constraint_source!(library_constraint)
      run!(*codesign, "--identifier", "#{BUNDLE_ID}.daemon", "--entitlements", "app/FloriaDaemon.entitlements", "--library-constraint", library_constraint, daemon)
      verify_embedded_library_constraint!(daemon)
      run!(*codesign, "--identifier", BUNDLE_ID, executable)
      app_sign = [*codesign, "--identifier", BUNDLE_ID]
      app_sign += ["--entitlements", signed_entitlements] unless profile.empty?
      run!(*app_sign, APP_BUNDLE)
      run!("codesign", "--verify", "--deep", "--strict", APP_BUNDLE)
      verify_signing(profile:, app: APP_BUNDLE) unless profile.empty?
      FileUtils.rm_f(signed_entitlements)
      run!(daemon, "--version", out: File::NULL)
      puts "==> Built: #{APP_BUNDLE}"
    end

    def package_dmg
      version = File.read(File.join(ROOT, "Cargo.toml"))[/^version = "([^"]+)"$/, 1]
      identity = ENV.fetch("SIGN_IDENTITY", "-")
      output = File.expand_path(ENV.fetch("OUTPUT_DMG", "build/#{APP_NAME}-#{version}.dmg"), ROOT)
      background = File.join(ROOT, "app/Assets/DmgBackground.tiff")
      raise "Refusing to overwrite existing DMG: #{output}" if File.exist?(output)
      raise "DMG background is missing; run mise run generate-dmg-background" unless File.file?(background)

      build_app
      FileUtils.mkdir_p(File.dirname(output))
      staging = Dir.mktmpdir("floria-dmg-stage.", ENV.fetch("TMPDIR", "/private/tmp"))
      mount = Dir.mktmpdir("floria-dmg-mount.", ENV.fetch("TMPDIR", "/private/tmp"))
      partial = File.join(File.dirname(output), ".#{File.basename(output)}.partial.#{$$}.dmg")
      writable = File.join(File.dirname(output), ".#{File.basename(output)}.writable.#{$$}.dmg")
      mounted = false
      begin
        run!("ditto", APP_BUNDLE, File.join(staging, "#{APP_NAME}.app"))
        FileUtils.ln_s("/Applications", File.join(staging, "Applications"))
        FileUtils.mkdir_p(File.join(staging, ".background"))
        FileUtils.cp(background, File.join(staging, ".background/DmgBackground.tiff"))
        run!("hdiutil", "create", "-volname", DMG_VOLUME_NAME, "-srcfolder", staging, "-format", "UDRW", "-fs", "HFS+", writable, out: File::NULL)
        run!("hdiutil", "attach", "-readwrite", "-noverify", "-noautoopen", "-mountpoint", mount, writable, out: File::NULL)
        mounted = true
        run!("chflags", "hidden", File.join(mount, ".background"))
        configure_finder(mount)
        run!("sync")
        run!("hdiutil", "detach", mount, "-quiet")
        mounted = false
        run!("hdiutil", "convert", writable, "-format", "UDZO", "-imagekey", "zlib-level=9", "-o", partial, out: File::NULL)
        FileUtils.rm_f(writable)
        unless identity == "-"
          run!("codesign", "--force", "--sign", identity, "--timestamp", partial)
          run!("codesign", "--verify", "--strict", partial)
        end
        run!("hdiutil", "verify", partial, out: File::NULL)
        run!("hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", mount, partial, out: File::NULL)
        mounted = true
        mounted_app = File.join(mount, "#{APP_NAME}.app")
        raise "DMG Applications link does not point to /Applications" unless File.readlink(File.join(mount, "Applications")) == "/Applications"
        raise "DMG visual layout metadata is incomplete" unless File.file?(File.join(mount, ".background/DmgBackground.tiff")) && File.file?(File.join(mount, ".DS_Store"))
        bundle = capture!("/usr/libexec/PlistBuddy", "-c", "Print :CFBundleIdentifier", File.join(mounted_app, "Contents/Info.plist")).strip
        raise "DMG app has the wrong bundle identifier" unless bundle == BUNDLE_ID

        run!("codesign", "--verify", "--deep", "--strict", mounted_app)
        run!("hdiutil", "detach", mount, "-quiet")
        mounted = false
        FileUtils.mv(partial, output)
        puts "==> DMG: #{output}"
      ensure
        mounted = false if mounted && system("hdiutil", "detach", mount, "-quiet")
        FileUtils.rm_rf(staging)
        unless mounted
          FileUtils.rm_rf(mount)
          FileUtils.rm_f([partial, writable])
        end
      end
    end

    def notarize(dmg)
      dmg = File.expand_path(dmg, ROOT)
      raise "DMG does not exist: #{dmg}" unless File.file?(dmg)

      credentials = if ENV["NOTARY_PROFILE"]&.then { !_1.empty? }
                      ["--keychain-profile", ENV.fetch("NOTARY_PROFILE")]
                    else
                      ["--apple-id", ENV.fetch("NOTARIZE_APPLE_ID"), "--team-id", ENV.fetch("APPLE_TEAM_ID"), "--password", ENV.fetch("NOTARIZE_PASSWORD")]
                    end
      run!("xcrun", "notarytool", "submit", dmg, *credentials, "--wait")
      run!("xcrun", "stapler", "staple", dmg)
      run!("xcrun", "stapler", "validate", dmg)
      run!("spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "--verbose=2", dmg)
      puts "==> Notarized: #{dmg}"
    end

    def verify_signing(profile:, app: nil)
      entitlements = profile_entitlements(profile)
      expected = {
        "com.apple.application-identifier" => "#{ENV.fetch("FLORIA_SIGNING_TEAM_ID")}.#{BUNDLE_ID}",
        "com.apple.developer.team-identifier" => ENV.fetch("FLORIA_SIGNING_TEAM_ID"),
        "com.apple.developer.icloud-container-environment" => "Production"
      }
      expected.each { |key, value| raise "#{key} is not #{value}" unless entitlements[key] == value }
      raise "profile does not authorize #{CONTAINER_ID}" unless entitlements.fetch("com.apple.developer.icloud-container-identifiers").include?(CONTAINER_ID)
      services = entitlements.fetch("com.apple.developer.icloud-services")
      raise "profile does not authorize CloudKit" unless services == "*" || services.include?("CloudKit")
      return unless app

      path = File.join(Dir.tmpdir, "floria-entitlements.#{$$}.abstract")
      run!("codesign", "-d", "--entitlements", path, app, err: File::NULL)
      values = abstract_entitlements(File.read(path))
      expected.merge(
        "com.apple.developer.icloud-container-identifiers" => CONTAINER_ID,
        "com.apple.developer.icloud-services" => "CloudKit"
      ).each { |key, value| raise "signed app does not claim #{value}" unless values.fetch(key, []).include?(value) }
    ensure
      FileUtils.rm_f(path) if path
    end

    def verify_library_constraint_source!(path)
      constraint = JSON.parse(capture!("plutil", "-convert", "json", "-o", "-", path))
      expected = { "team-identifier" => MACFUSE_TEAM_ID }
      raise "macFUSE library constraint must be exactly #{expected}" unless constraint == expected
    end

    def verify_embedded_library_constraint!(executable)
      dump = capture_combined!("codesign", "--display", "--verbose=6", executable)
      embedded_team = /\[Key\] team-identifier\s+\[Value\]\s+\[String\] #{MACFUSE_TEAM_ID}/m
      unless dump.include?("Has Library Load Constraints") && dump.match?(embedded_team)
        raise "signed daemon does not embed the exact macFUSE Team ID library constraint"
      end
    end

    private

    def profile_entitlements(profile)
      xml = capture!("security", "cms", "-D", "-i", profile)
      JSON.parse(capture!("plutil", "-extract", "Entitlements", "json", "-o", "-", "--", "-", stdin_data: xml))
    end

    def abstract_entitlements(text)
      key = nil
      text.each_line.each_with_object(Hash.new { |hash, name| hash[name] = [] }) do |line, values|
        key = line.sub(/^\s*\[Key\]\s+/, "").strip if line.match?(/^\s*\[Key\]/)
        values[key] << line.sub(/^\s*\[String\]\s+/, "").strip if key && line.match?(/^\s*\[String\]/)
      end
    end

    def finder_script(disk)
      <<~APPLESCRIPT
        tell application "Finder"
          tell disk "#{disk}"
            open
            set current view of container window to icon view
            set toolbar visible of container window to false
            set statusbar visible of container window to false
            set pathbar visible of container window to false
            -- Finder bounds include the 32 pt title bar. A 452 pt outer height
            -- leaves the icon view at the background's full 420 pt height.
            set the bounds of container window to {120, 120, 780, 572}
            set viewOptions to the icon view options of container window
            set arrangement of viewOptions to not arranged
            set icon size of viewOptions to 96
            set text size of viewOptions to 13
            set background picture of viewOptions to file ".background:DmgBackground.tiff"
            set position of item "#{APP_NAME}.app" of container window to {180, 235}
            set position of item "Applications" of container window to {480, 235}
            update without registering applications
            delay 1
            close
          end tell
        end tell
      APPLESCRIPT
    end

    def configure_finder(mount)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      begin
        run!("/usr/bin/osascript", "-", stdin_data: finder_script(File.basename(mount)))
      rescue RuntimeError
        raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.25
        retry
      end
    end
  end
end
