# Use the official PostgreSQL 13.5 image from Docker Hub
FROM postgres:13.5

# Install dependencies for Liquibase
RUN apt-get update && apt-get install -y \
    openjdk-11-jdk \
    wget \
    unzip \
    && apt-get clean

# Set environment variables for Liquibase
ENV LIQUIBASE_VERSION=4.6.1
ENV LIQUIBASE_HOME=/opt/liquibase

RUN mkdir -p ${LIQUIBASE_HOME}

# Download and install Liquibase
RUN wget https://github.com/liquibase/liquibase/releases/download/v${LIQUIBASE_VERSION}/liquibase-${LIQUIBASE_VERSION}.tar.gz -O /tmp/liquibase.tar.gz && \
    tar -xf /tmp/liquibase.tar.gz -C ${LIQUIBASE_HOME} && \
    rm /tmp/liquibase.tar.gz && \
    ln -s ${LIQUIBASE_HOME}/liquibase /usr/local/bin/liquibase

# Add Liquibase to the PATH
ENV PATH="${LIQUIBASE_HOME}:${PATH}"

# Verify installation
RUN ${LIQUIBASE_HOME}/liquibase --version

# Set the working directory to /config
WORKDIR /config

# Copy configuration files
COPY ./target/master.xml /config/master.xml
COPY ./target/sql/ /config/sql/
COPY ./initialize-db.sh /initialize-db.sh

# Ensure the initialize-db.sh script is executable
RUN chmod +x /initialize-db.sh

# Expose the PostgreSQL port
EXPOSE 5432

# Set the entrypoint to run PostgreSQL
ENTRYPOINT ["/initialize-db.sh"]

#Command to run the initialize-db.sh script after PostgreSQL starts
CMD ["postgres"]