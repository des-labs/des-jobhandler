Example task definition for Kubernetes Jobs
-------------------------------------------

This folder contains the files needed to define a "task" that will be accomplished by spawning a Kubernetes Job. The primary components are the files

* `Dockerfile`
* `task.py`

The `Dockerfile` is used to build the image that will define the Pod that the Job creates once launched by Kubernetes. By convention, the container will execute the command `python task.py` to accomplish the desired task.
