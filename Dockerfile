# Base image `riateche/ritual_builder` is built
# from `docker.builder.dockerfile` in the ritual repository.
FROM riateche/ritual_builder
# Install the target C++ library.
RUN apt-get update && \
    apt-get install -y libgmp-dev libssl-dev cmake nano

ADD bicycl-master bicycl-master 
ADD Cargo.toml Cargo.toml
ADD crate_template crate_template
ADD src src

RUN rustup default nightly

RUN mkdir /bicycl_build && \
    cd /bicycl_build && \
    cmake /bicycl-master/ && \
    make && \
    make install 

# If your library is not in system directories, adjust
# environment variables to allow ritual and the generated crate
# find the library.
ENV INCLUDE_PATH=/usr/local/include/bicycl
ENV RITUAL_INCLUDE_PATH=/usr/local/include/bicycl
ENV LIBRARY_PATH=/usr/local/lib
ENV LD_LIBRARY_PATH=/usr/local/lib
