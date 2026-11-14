FROM swift:6.1

# Add nonroot user
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

# Create app directory as root
RUN mkdir -p /home/nonroot && chown -R nonroot:nonroot /home/nonroot
RUN mkdir -p /home/nonroot/src/app && chown -R nonroot:nonroot /home/nonroot/src/app
USER nonroot

# Change working dir to /usr/src/app
WORKDIR /home/nonroot/src/app
VOLUME /home/nonroot/src/app

# The C target lives in Dependencies/ (smb2-module shim + libsmb2 submodule);
# swift-system/swift-atomics are fetched from the registry at build time.
COPY Package.swift ./
COPY AMSMB2 ./AMSMB2
COPY AMSMB2Tests ./AMSMB2Tests
COPY Dependencies ./Dependencies

ENTRYPOINT ["swift", "test"]
