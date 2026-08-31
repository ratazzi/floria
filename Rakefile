# frozen_string_literal: true

require "base64"
require "fileutils"
require "rake"
require "tmpdir"
require_relative "rakelib/release"

desc "Run the same checks as GitHub CI"
task :ci do
  sh "mise run check-rust-fixtures"
  sh "cargo test --workspace --features floria/macos-no-mount"
  sh "cargo clippy --workspace --all-targets --features floria/macos-no-mount -- -D warnings"
  sh "swift test --package-path app"
  sh "bash -n scripts/install-app scripts/smoke-daemon-recovery"
end

task(:build_app) { Floria::Release.build_app }
task(:package_dmg) { Floria::Release.package_dmg }
task(:notarize_dmg) { Floria::Release.notarize(ENV.fetch("DMG_PATH")) }

desc "Build, sign, notarize, and verify the macOS release artifact"
task :release do
  profile = File.join(ENV.fetch("RUNNER_TEMP", Dir.tmpdir), "Floria.provisionprofile")
  File.umask(0o077)
  File.binwrite(profile, Base64.decode64(ENV.fetch("FLORIA_APP_PROVISIONING_PROFILE_BASE64")))
  begin
    env = {
      "BUILD_NUMBER" => ENV.fetch("GITHUB_RUN_NUMBER", Time.now.strftime("%Y%m%d%H%M")),
      "SIGN_IDENTITY" => ENV.fetch("DEVELOPER_ID_IDENTITY"),
      "FLORIA_SIGNING_TEAM_ID" => ENV.fetch("APPLE_TEAM_ID"),
      "FLORIA_APP_PROVISIONING_PROFILE" => profile
    }
    env.each { ENV[_1] = _2 }
    Floria::Release.package_dmg
    dmg = Dir["build/Floria-*.dmg"].then do |matches|
      raise "expected exactly one release DMG, found #{matches.length}" unless matches.one?

      matches.first
    end
    Floria::Release.notarize(dmg)
  ensure
    FileUtils.rm_f(profile)
  end
end
