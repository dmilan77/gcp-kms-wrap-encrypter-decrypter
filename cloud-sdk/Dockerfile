FROM google/cloud-sdk:289.0.0-alpine
ENV APP_HOME /app

COPY pgp-key-gen.sh /app/
COPY gpg-config.txt /app/
# COPY gcp-sa.json /app/
# RUN chmod +x  /app/pgp-key-gen.sh
RUN ls -l /app/
ENTRYPOINT [ "/app/pgp-key-gen.sh" ]
CMD ["/bin/bash"]