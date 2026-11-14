test:
	swift test

asan-test:
	swift test --sanitize=address --filter "SMB2LifetimeTests|SMB2RegressionTests|SMB2FileStatTests|SMB2TimestampTests"

# Builds a self-contained image: the image resolves its own dependencies, so
# the result does not depend on the host's Package.resolved or .build. (A
# volume-mounted variant used to exist; it inherited the host's resolved
# versions and broke whenever those needed a newer toolchain than the image.)
cleanlinuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm linuxtest
