use std::collections::HashMap;
use std::sync::Arc;

use floria_core::config::{FileEntry, SECRETS_DIR, SURFACES_DIR};
use floria_core::source::ContentSource;

/// Root inode. FUSE convention: root = 1.
const ROOT_INO: u64 = 1;

pub struct Tree {
    nodes: HashMap<u64, Node>,
    by_parent_name: HashMap<(u64, String), u64>,
    children: HashMap<u64, Vec<u64>>,
    /// Inode of the always-present `secrets/` directory. Its children are resolved dynamically
    /// against the store (not stored here), so `protect` is visible without remounting.
    secrets_dir_ino: u64,
    /// Inode of the always-present catalog surface directory. Its children come from the
    /// in-memory surface registry maintained by the control plane.
    surfaces_dir_ino: u64,
    /// First inode not used by the static tree; dynamic namespaces allocate from here.
    next_ino: u64,
}

pub struct Node {
    pub parent: u64,
    pub name: String,
    pub mode: u16,
    pub kind: NodeKind,
}

impl Node {
    /// Returns a file node's virtual path; directories return an empty string.
    pub fn virtual_path(&self) -> String {
        match &self.kind {
            NodeKind::File(f) => f.virtual_path.clone(),
            NodeKind::Dir => String::new(),
        }
    }
}

pub enum NodeKind {
    Dir,
    File(FileNode),
}

pub struct FileNode {
    pub source: Arc<dyn ContentSource>,
    pub virtual_path: String,
    /// Stable size reported by getattr. Constant files = exact length; script files = declared upper bound.
    pub report_size: u64,
    /// Script (dynamic) files use direct-io to avoid the kernel truncating to attr size / caching across opens.
    pub direct_io: bool,
}

impl Tree {
    /// Build the static inode tree from the resolved virtual files (config files plus any
    /// store-backed secrets). inodes are assigned sequentially and never reclaimed during the mount.
    pub fn build(files: &[FileEntry]) -> Self {
        let mut tree = Tree {
            nodes: HashMap::new(),
            by_parent_name: HashMap::new(),
            children: HashMap::new(),
            secrets_dir_ino: 0,
            surfaces_dir_ino: 0,
            next_ino: 0,
        };
        tree.nodes.insert(
            ROOT_INO,
            Node {
                parent: ROOT_INO,
                name: String::new(),
                mode: 0o555,
                kind: NodeKind::Dir,
            },
        );
        tree.children.insert(ROOT_INO, Vec::new());

        let mut next_ino = ROOT_INO + 1;
        for entry in files {
            // Ensure each intermediate directory exists, level by level, to get the final parent directory's inode.
            let mut parent = ROOT_INO;
            let dirs = &entry.components[..entry.components.len() - 1];
            for dir_name in dirs {
                parent = tree.ensure_dir(parent, dir_name, &mut next_ino);
            }

            // The last component is the file itself.
            let file_name = entry
                .components
                .last()
                .expect("validated non-empty path")
                .clone();
            let (report_size, direct_io) = match entry.source.exact_size() {
                Some(size) => (size, false),
                // Computed sources are dynamic: direct-io, size is the declared upper bound.
                None => (entry.declared_size.unwrap_or(0), true),
            };

            let ino = next_ino;
            next_ino += 1;
            tree.nodes.insert(
                ino,
                Node {
                    parent,
                    name: file_name.clone(),
                    mode: entry.mode,
                    kind: NodeKind::File(FileNode {
                        source: Arc::clone(&entry.source),
                        virtual_path: entry.path.clone(),
                        report_size,
                        direct_io,
                    }),
                },
            );
            tree.by_parent_name.insert((parent, file_name), ino);
            tree.children.entry(parent).or_default().push(ino);
        }

        // Surface children are supplied by the live in-memory registry in the fs layer.
        let surfaces_dir_ino = tree.ensure_dir(ROOT_INO, SURFACES_DIR, &mut next_ino);
        tree.surfaces_dir_ino = surfaces_dir_ino;

        // Always expose a top-level `secrets/` directory; its children are resolved dynamically
        // by the fs layer against the store, so newly protected files appear without a remount.
        let secrets_dir_ino = tree.ensure_dir(ROOT_INO, SECRETS_DIR, &mut next_ino);
        tree.secrets_dir_ino = secrets_dir_ino;
        tree.next_ino = next_ino;

        tree
    }

    /// Inode of the `secrets/` directory.
    pub fn secrets_dir_ino(&self) -> u64 {
        self.secrets_dir_ino
    }

    pub fn surfaces_dir_ino(&self) -> u64 {
        self.surfaces_dir_ino
    }

    /// First inode not used by the static tree (start of the dynamic secrets range).
    pub fn next_ino(&self) -> u64 {
        self.next_ino
    }

    /// Returns the inode for the `(parent, name)` directory, creating it if it doesn't exist.
    fn ensure_dir(&mut self, parent: u64, name: &str, next_ino: &mut u64) -> u64 {
        if let Some(&ino) = self.by_parent_name.get(&(parent, name.to_string())) {
            return ino;
        }
        let ino = *next_ino;
        *next_ino += 1;
        self.nodes.insert(
            ino,
            Node {
                parent,
                name: name.to_string(),
                mode: 0o555,
                kind: NodeKind::Dir,
            },
        );
        self.by_parent_name.insert((parent, name.to_string()), ino);
        self.children.entry(parent).or_default().push(ino);
        self.children.entry(ino).or_default();
        ino
    }

    pub fn get(&self, ino: u64) -> Option<&Node> {
        self.nodes.get(&ino)
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.by_parent_name.get(&(parent, name.to_string())).copied()
    }

    pub fn children(&self, ino: u64) -> &[u64] {
        self.children.get(&ino).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_namespaces_have_stable_directories() {
        let tree = Tree::build(&[]);
        assert_eq!(
            tree.lookup_child(ROOT_INO, SURFACES_DIR),
            Some(tree.surfaces_dir_ino())
        );
        assert_eq!(
            tree.lookup_child(ROOT_INO, SECRETS_DIR),
            Some(tree.secrets_dir_ino())
        );
        assert_ne!(tree.surfaces_dir_ino(), tree.secrets_dir_ino());
    }
}
