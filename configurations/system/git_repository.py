class GitRepository:
    def __init__(self, owner, name, branch, url=None):
        self.owner = owner
        self.name = name
        self.branch = branch
        self.url = url 

