# Git Cookbook

### Caching your git credentials
    git config credential.helper "cache --timeout=86400"

### Creating a local branch from the release tag and merging your commits
From the master branch

    git pull -t
    git checkout -b localbranch release

To commit your changes

    git commit -am "Your commit message"
    git checkout production
    git merge localbranch
    git push
    git checkout master
    git merge localbranch
    git push

### Update and push a new 'release' tag

From your master branch

	git tag -f release
	git push -f origin release

### Checkout from the 'release' tag

You cannot simply checkout the tag in your current master branch.
Instead, you create a transient branch based on the release tag:

	git checkout -b release release

Note: If you have an old release branch you may need to delete that first before syncing:

	git branch -D release release

### Worker BootStrap Recipe

The current bootstrap on the worker boxes is:

#### Fetch most recent repo
	git fetch && git checkout master && git reset --hard origin/master

#### Delete any existing 'release' branch
	git branch -D release 2> /dev/null

#### Checkout current release branch
	git checkout -b release release
