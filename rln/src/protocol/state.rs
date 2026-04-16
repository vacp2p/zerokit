#[derive(Debug, Clone)]
pub struct Stateful<T> {
    pub tree: T,
}

impl<T> Stateful<T> {
    pub fn new(tree: T) -> Self {
        Self { tree }
    }

    pub fn tree(&self) -> &T {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut T {
        &mut self.tree
    }

    pub fn into_tree(self) -> T {
        self.tree
    }
}

#[derive(Debug, Clone)]
pub struct Stateless;
