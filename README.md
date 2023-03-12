# Class Group DKG
We use [bicycl](https://gite.lirmm.fr/crypto/bicycl) library for class group implementation. As bicycl library is written in C++, we need to generate ffi bindings to use bicycl in rust. 
We use [ritual](https://github.com/rust-qt/ritual) library to generate ffi bindings. Ritual uses docker to generate ffi bindings. 
To generate bindings for bicycl use the following steps:

### Build the docker image
```
docker build . -t bicycl_generator
```
### Remove previously created container
```
docker ps -a -q --filter "name=bicycl_generator" | grep -q . && \
    docker rm bicycl_generator
```
### Create a container and mount local directories to be used while generating bindings
Change the directory paths as needed in the following command.
```
docker run --mount type=bind,source=/change/to/current/repo/,destination=/repo --mount type=bind,source=/change/to/current/repo/workspace,destination=/workspace --mount type=bind,source=/change/to/current/repo/tmp/,destination=/build --name bicycl_generator --hostname bicycl_generator -it bicycl_generator
```
### Generate bindings
```
cargo run -- workspace -c bicycl -o main
```
The generated bindings are stored in the workspace directory.
