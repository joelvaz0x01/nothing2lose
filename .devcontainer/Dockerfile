# Python version (use -bookworm or -bullseye variants on local arm64/Apple Silicon)
ARG VARIANT=3-bookworm
FROM python:${VARIANT}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    # Remove imagemagick due to https://security-tracker.debian.org/tracker/CVE-2019-10131
    && apt-get purge -y imagemagick imagemagick-6-common 

# Temporary: Upgrade python packages due to https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40897 and https://github.com/advisories/GHSA-2mqj-m65w-jghx
# They are installed by the base image (python) which does not have the patch.
RUN python3 -m pip install --upgrade \
    setuptools==69.0.3 \
    gitpython==3.1.41

COPY requirements.txt /tmp/pip-tmp/
RUN pip3 --disable-pip-version-check --no-cache-dir install -r /tmp/pip-tmp/requirements.txt \
    && rm -rf /tmp/pip-tmp

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install sudo git procps \
	# Add vscode user
	&& groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid 1000 -m vscode \
    && echo vscode ALL=\(ALL\) NOPASSWD: ALL > /etc/sudoers.d/vscode \
    && chmod 0440 /etc/sudoers.d/vscode
