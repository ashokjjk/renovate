# Nexus Platform Core

This Readme will guide you through the different steps required to develop your own application and deploy it
in to the nexus platform.

The commit history will be used as steps that you can follow to understand the workflow and the involved parts.

### Pre-requisites


Run the wsl2-setup.sh script according to
[nexus-platform repo](https://bitbucket.org/ifs-pd/nexus-platform/src/main/)
It will install all the required tools for the process.
Cloning the repo will be useful in later steps anyway.


### Steps

1. [Coding your app](#coding)
    1. [Base coding](#base-coding)
    2. [Testing app](#testing-1)
2. [Containerization](#container)
    1. [Create Image/s](#create-image)
    2. [Testing Image](#testing-2)
    3. [Pushing Local Registry](#pushing-local)
3. [Helm Chart Creation](#helm-chart)
    1. [Create manifests](#creating-manifests)
    2. [Nexus-cli local cluster](#nexus-cli)
    3. [Testing Chart](#testing-3)
    4. [Pushing Chart (ACR)](#pushing-chart)
4. [Local Platform integration](#local-platform)
    1. [Bundle](#bundle)
    2. [Pushing Bundle (ACR)](#pushing-acr)
    3. [Testing Gitops](#testing-4)
5. [Deployment to Stage](#deployment)
6. [Update your app](#update)

### Step 1 - Coding your app <a name="coding" id="coding"></a>

In this demo we are going to code a simple Go language API that would contain two endpoints

- GET /health
- POST /echo

The first one will be useful and handy to check if our application is alive, the second one does an echo of the request payload

#### 1.1 Base coding <a name="base-coding" id="base-coding"></a>

```bash
mkdir src
cd src
go mod init nexus.ifs.com
touch main.go main_test.go

```

**[main.go](src/main.go)**
**[main_test.go](src/main_test.go)**

We create main.go and code our api inside
create main_test.go and do our routes tests
finally did some integration test using the curl client with test.sh

```
 .
├──  src
│ ├──  go.mod
│ ├──  go.sum
│ ├──  main.go
│ └──  main_test.go
└──  test.sh

```

#### 1.2 Testing <a name="testing-1" id="testing-1"></a>

```bash

touch test.sh
chmod+x test.sh

```

**[test.sh](test.sh)**
**[test-chart.sh](test-chart.sh)**

```

How to test and execute (make sure you are inside of src folder):

```bash
go test
go run main.go
(optional port spec)
go run main.go --port 9090
cd ..
chmod +x test.sh
./test.sh 9090

```

### Step 2 - Containerization <a name="container" id="container"></a>

We need our app to be wrapped as a docker image in order to be able to be deployed in the nexus platform

Create the DockerFile that handles the go api containerization.

#### 2.1 Create Image/s <a name="create-image" id="create-image"></a>

```bash
touch Dockerfile

```

And code it accordingly:

**[Dockerfile](Dockerfile)**

```

#### 2.2 Testing <a name="testing-2" id="testing-2"></a>

Then we build the image and verify that works correctly:

```bash

docker build -t my-app .
docker run -p 9090:9090 my-app --por
t=9090
./test.sh 9090

```

#### 2.3 Pushing Local Registry <a name="pushing-local" id="pushing-local"></a>

We need to define a Makefile that will drive the build and push into the local registry

**[Makefile](Makefile)**

```

Then we run make

```bash
make

```

import-image target will be used later in step 3.4 . [Pushing (ACR)](<#pushing-(acr)>)

we can confirm that image is there with:

```bash
curl -X GET http://localhost:5000/v2/_catalog | jq

```

### Step 3 - Helm Chart Creation <a name="helm-chart" id="helm-chart"></a>

Now that we have the a working image, we need to wrap it as a helm chart so it can be installed in the kubernetes clusters that nexus platform manages using GitOps paradigm

#### 3.1 Creating manifests <a name="creating-manifests" id="creating-manifests"></a>

```bash

mkdir chart
mkdir chart/templates
touch chart/templates/echo-api.yaml
touch chart/Chart.yaml
touch chart/Makefile
touch chart/values.yaml

```

Right now our project structure looks like this:

```
 .
├──  chart
│  ├──  Chart.yaml
│  ├──  Makefile
│  ├──  templates
│  │  └──  echo-api.yaml
│  └──  values.yaml
├──  Dockerfile
├──  Makefile
├──  README.md
├──  src
│  ├──  go.mod
│  ├──  go.sum
│  ├──  main.go
│  └──  main_test.go
└──  test.sh

```

We need to code all the fiels that we have scaffolded

[chart/templates/configmap.yaml](chart/templates/configmap.yaml)
[chart/templates/deployment.yaml](chart/templates/deployment.yaml)
[chart/templates/service.yaml](chart/templates/service.yaml)
[chart/templates/ingress.yaml](chart/templates/ingress.yaml)
[chart/templates/namespace.yaml](chart/templates/namespace.yaml)


```

#### 3.2 Nexus cli local cluster <a name="nexus-cli" id="nexus-cli"></a>

Spawn a local cluster to test our helm chart behavior. Use the nexus cli that comes with the nexus-platform repo under cli folder.

You can create a symbolic link in a directory that's in your PATH, or add an alias in your shell profile. Here's how to do both:

1. **Creating a symbolic link**

You can create a symbolic link in the `/usr/local/bin` directory, which is commonly included in the system's PATH:

```bash
sudo ln -s ~/projects/nexus-platform/cli/nexus /usr/local/bin/nexus
```

2. **Adding an alias**

You can add an alias in your shell profile. If you're using bash, you can add it to `~/.bashrc`. If you're using zsh, you can add it to `~/.zshrc`:

```bash
echo 'alias nexus="~/projects/nexus-platform/cli/nexus"' >> ~/.bashrc
echo 'alias nexus="~/projects/nexus-platform/cli/nexus"' >> ~/.zshrc
```

After adding the alias, you need to source your profile to make the alias available in your current shell:
it has a full README about how to use it.

[nexus-cli](https://bitbucket.org/ifs-pd/nexus-platform/src/main/cli/README.md)

Quick setup:

-Create a git bitbucket repository named nexus-local-gitops.git so it can be used later for gitps, now is just part of spawning a local cluster.
-Create an ssh key and configure the repo with it

```bash
# Generate a new SSH key pair
ssh-keygen -t rsa -b 4096 -C "your_email@ifs.com" -f ~/.ssh/argo

# Ensure the SSH agent is running
eval "$(ssh-agent -s)"

# Add the new key to the SSH agent
ssh-add ~/.ssh/argo
```

copy the genrated public key in Repository settings -> access keys -> add key

```bash
cat ~/.ssh/argo.pub

```

```bash
./nexus cluster create -p <nexus-platform-acr-pass> -sr  git@bitbucket.org:<your-user>/nexus-local-gitops.git -sd  ~/nexus/local-state/ -b main -kf ~/.ssh
/argo -is'

```

After 2-4 min the local cluster will be ready and you will be notified. You can use k9s to check the status

#### 3.3 Testing Chart <a name="testing-3" id="testing-3"></a>

```bash

touch test-chart.sh
chmod+x test-chart.sh

```

**[test-chart.sh](test-chart.sh)**
```

Run this automated chart test script with:

```bash
./test-chart.sh
```

It does some simple steps for us in an automated way. Compile the chart and apply it to the cluster.

Then we can proceed to ping our api again to verify that everything
remains in place.

```bash
./test.sh 8443 https
```

#### 3.4 Pushing Chart (ACR) <a name="pushing-chart" id="pushing-chart"></a>

Now that we have a working application as helm chart, let's upload it to the nexus platform ACR so it becames avaialble
for local and deployed gitops platform.

**Uploading images**

```bash
make import-image
```

```
Copying image from localhost:5000/nexus/echo-api:latest to nxsnprglb01acr.azurecr.io/nexus/echo-api:latest for all platforms
Manifests: 3/3 | Blobs: 4.236MB copied, 0.000B skipped | Elapsed: 6s
nxsnprglb01acr.azurecr.io/nexus/echo-api:latest
```

Next step is to push the chart itself to the same registry.

```bash
cd chart && make push
```

```
Successfully packaged chart and saved it to: /home/cesar/projects/dev-demo/chart/echo-go-api-0.1.0.tgz
pushing echo-go-api-0.1.0.tgz to oci://nxsnprglb01acr.azurecr.io/helm
Pushed: nxsnprglb01acr.azurecr.io/helm/echo-go-api:0.1.0
```

### Step 4 - Local platform integration <a name="local-platform" id="local-platform"></a>

Our next goal is to integrate our development with the gitops flow of the nexus locally deployed platform
We will need to prepare a bundle and modify the local state repo state to make it pick our application.

#### 4.1 Bundle <a name="bundle" id="bundle"></a>

[Bundle explanation](https://bitbucket.org/ifs-pd/nexus-gitops/src/main/)

Let's create our own:

**bash at the root of dev-demo**

```bash
mkdir bundle && \
mkdir bundle/chart && \
mkdir bundle/chart/templates && \
touch bundle/chart/templates/echo-api-app.yaml && \
touch bundle/chart/Chart.yaml && \
touch bundle/chart/Makefile && \
touch bundle/chart/values.yaml
```

```
 .
├──  bundle
│  └──  chart
│     ├──  Chart.yaml
│     ├──  Makefile
│     ├──  templates
│     │  └──  echo-api-app.yaml
│     └──  values.yaml

```

**[Chart.yaml](bundle/chart/Chart.yaml)**

**[values.yaml](bundle/chart/values.yaml)**

**[echo-api-app.yaml](bundle/chart/templates/echo-api-app.yaml)**

**[Makefile](bundle/chart/Makefile)**

```

#### 4.2 Publish ACR <a name="publish-acr" id="publish-acr"></a>

Inside bundle folder we publish the bundle in ACR so it could be picked by local-state repo

```bash
cd chart && make push
```

#### 4.3 Testing Gitops <a name="testing-4" id="testing-4"></a>

Our goal at this time is to update de desired state repo (local-state) https://bitbucket.org/<ifs-username>/nexus-local-gitops
that we created previously.

We want to deliver the bundle-echo-api to the local cluster through argocd gitops.

Let's open other bash pointing to the local state repo:

```bash
cd ~/nexus/local-state
```

Here we need to do add at least 3 files:

- AppSet manifest to spawn our previously defined bundle in ./dev/applications
- Argo project related with the created app/s in ./dev/projects
- A version definition of our bundle in ./dev/rings/local/chart-versions with the proper naming for the manifest

```bash
touch dev/applications/echo-api.app-set.yaml
touch dev/projects/echo-api.yaml
echo "version: 0.1.0" > dev/rings/local/chart-versions/echo-api.yaml
```

**/dev/applications/echo-api.app-set.yaml**

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: echo-api
spec:
  goTemplate: true
  goTemplateOptions: ["missingkey=error"]
  generators:
    - matrix:
        generators:
          - clusters:
              # skip the local cluster
              selector:
                matchLabels:
                  argocd.argoproj.io/secret-type: cluster
                  ifs.com/ring: local
              values:
                ring: '{{ index .metadata.labels "ifs.com/ring" }}'
                region: '{{ index .metadata.labels "ifs.com/region" }}'
                stage: '{{ index .metadata.labels "ifs.com/stage" }}'
          - git:
              repoURL: "git@bitbucket.org:ifs-cslues/nexus-local-gitops.git"
              revision: main
              files:
                - path: "{{ .values.stage }}/rings/{{ .values.ring }}/chart-versions/echo-api.yaml"
  template:
    metadata:
      name: bundle-echo-api-{{ .nameNormalized }}
      labels:
        ifs.com/component: echo-api
        ifs.com/cluster: "{{ .name }}"
        ifs.com/ring: "{{ .values.ring }}"
        ifs.com/region: "{{ .values.region }}"
    spec:
      project: echo-api
      destination:
        namespace: argocd
        server: "{{ .server }}"
      sources:
        - chart: bundle-echo-api
          repoURL: nxsnprglb01acr.azurecr.io/helm
          targetRevision: '{{.version}}'
          helm:
            ignoreMissingValueFiles: true
            releaseName: echo-api
            values: |
              clusterName: '{{ .nameNormalized }}'
              destinationServer: '{{ .server }}'
              inClusterConfiguration: true
              localCluster: true
            valueFiles:
              - $values/{{ .values.stage }}/global/echo-api.values.yaml
              - $values/{{ .values.stage }}/regions/{{ .values.region }}/echo-api.values.yaml
              - $values/{{ .values.stage }}/rings/{{ .values.ring }}/echo-api.values.yaml
              - $values/{{ .values.stage }}/clusters/{{.name}}/echo-api.values.yaml
        - repoURL: 'git@bitbucket.org:ifs-cslues/nexus-local-gitops.git'
          targetRevision: main
          ref: values
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
          allowEmpty: true
        syncOptions:
          - PrunePropagationPolicy=foreground
          - CreateNamespace=true
          - ServerSideApply=true

```

**/dev/projects/echo-api.yaml**

```yaml

apiversion: argoproj.io/v1alpha1
kind: appproject
metadata:
  name: echo-api
  namespace: argocd
spec:
  clusterresourcewhitelist:   # todo: we should impose proper restrictions to limit what may be deployed in this project
    - group: '*'
      kind: '*'
  destinations:
    - namespace: argocd
      server: "https://kubernetes.default.svc"
    - namespace: dev-demo
      server: "https://kubernetes.default.svc"
  namespaceresourcewhitelist:   # todo: we should impose proper restrictions to limit what may be deployed in this project
    - group: '*'
      kind: '*'
  sourcerepos:
    - nxsnprglb01acr.azurecr.io/helm
    - git@bitbucket.org:ifs-cslues/nexus-local-gitops.git
```

#### 4.4 Continous development <a name="continuous-development" id="continuous-development"></a>

In case that is becoming hard to trace what is not working or if you want to iterate as you develop your bundle, you can link a local bundle to argocd.
This way it would be much quicker to test your changes and won't require continous bundle pushes to ACR.

<!--TO-DO show example of setup-->

### Step 5 - Deployment to stage <a name="deployment" id="deployment"></a>

In this step we want to deploy our bundle in a real live platform cluster/s. Potentially Azure AKS. In this case we need to modify the desired-state repository instead of the local one:

[desired-state-repo](https://bitbucket.org/ifs-pd/nexus-gitops/src/main/?search_id=356ca21b-2cf2-4dfa-9355-ab3ff28473fd)

Clone the repo and add the same kind of files that we created locally but with subtle adaptations:

<!--TO-DO show example of setup-->


### Step 6 - Update your application <a name="update" id="update"></a>

