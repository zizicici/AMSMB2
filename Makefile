test:
	swift test

asan-test:
	swift test --sanitize=address --filter "SMB2LifetimeTests|SMB2RegressionTests|SMB2FileStatTests|SMB2TimestampTests"

linuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm -v .:/home/nonroot/src/app linuxtest

cleanlinuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm linuxtest
