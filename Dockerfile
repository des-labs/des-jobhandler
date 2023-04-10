FROM registry.gitlab.com/des-labs/kubernetes/easyaccess:1.4.12

ARG UID=68586
ARG GID=2402
RUN groupmod -g ${GID} worker && usermod -u ${UID} -g ${GID} worker

WORKDIR /home/worker
USER worker

# Next, install the required Python modules:
COPY --chown=worker:worker ./requirements.txt .
RUN pip3 install --user -r requirements.txt
# Install required modules for cutout service when running synchronously
COPY --chown=worker:worker ./des_tasks/cutout/worker/requirements.txt ./requirements_cutouts.txt
RUN pip3 install --user -r requirements_cutouts.txt

COPY --chown=worker:worker ./ .

CMD ["/bin/bash", "-c", "bash backend.entrypoint.sh"]
