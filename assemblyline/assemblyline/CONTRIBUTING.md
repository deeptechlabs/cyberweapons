# Assemblyline contributing guide

This guide covers the basics of how to contribute to the Assemblyline project.

Python code should follow the PEP8 guidelines defined here: [PEP8 Guidelines](https://www.python.org/dev/peps/pep-0008/).

## Tell us want you want to build/fix
Before you start coding anything you should connect with the [Assemblyline community](https://groups.google.com/d/forum/cse-cst-assemblyline) to make sure no one else is working on the same thing and that whatever you are going to build still fits with the vision off the system.

## Git workflow

- Clone the repo to your own account
- Checkout and pull the latest commits from the latest production branch (prod_x.x)
- Make a branch
- Work in any way you like and make sure you changes actually work
- When your satisfied with your changes, create two pull request to the main assemblyline repo:
   - One pull request to our master branch
   - Another to the latest production branch (prod_x.x)

#### Transfer your service repo
If you've worked on a new service that you want to be included in the default service selection you'll have to transfer the repo into our control.

#### You are not allow to merge:

Even if you try to merge in your pull request, you will be denied. Only a few people in our team are allow to merge code into our master and prod* branches.

We check for new pull request every day and will merge them in once they have been approved by someone in our team. Pull request will first be merged into the master branch and spend a few days/weeks there for testing, depending on the change. Then they will be merged in our latest production branch.
