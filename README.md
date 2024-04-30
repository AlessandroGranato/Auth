# Auth
Auth module with Spring boot and JWT technologies

## Project main guide
https://www.bezkoder.com/spring-boot-jwt-authentication/

## Using Docker to deploy
The steps to run the application in docker are the following:

### Ensure you have a working Docker instance
Ensure that Docker Desktop or similar are active.

### Ensure you have a docker network already up
If you don't have it, run the following command:
```
docker network create boogle-network
```

### Create docker images
To create the docker images of the db and the application, go on the root of the project and run:
```
mvn clean install -Plocal-image
```

If you only want to create only the db image, run the previous command from packager-db sumbodule instead of root.

If you only want to create only the application image, run the previous command from packager sumbodule instead of root.

### Run db docker container

To run a docker db container, run the following command and populate the db variables as you need:

```
docker run --name boogle-auth-db --network=boogle-network -e POSTGRES_DB=dbAuth -e POSTGRES_USER=dbAuth -e POSTGRES_PASSWORD=dbAuth -dp 127.0.0.1:5433:5432 pyrosandro/boogle-auth-db-image:0.0.1-SNAPSHOT
```

Command explanation:
1. **docker run:** This is the command to run a Docker container.
2. **--name boogle-auth-db:** This option specifies the name of the container as "boogle-auth-db". The --name flag allows you to assign a custom name to the container instead of Docker generating a random one.
3. **--network=boogle-network:** This option specifies the network to which the container should be attached. It connects the container to the "boogle-network" Docker network.
4. **-e POSTGRES_DB=dbAuth:** This option sets the environment variable POSTGRES_DB inside the container to "dbAuth". This variable is used to specify the name of the PostgreSQL database to be created inside the container.
5. **-e POSTGRES_USER=dbAuth:** This option sets the environment variable POSTGRES_USER inside the container to "dbAuth". This variable is used to specify the username for connecting to the PostgreSQL database.
6. **-e POSTGRES_PASSWORD=dbAuth:** This option sets the environment variable POSTGRES_PASSWORD inside the container to "dbAuth". This variable is used to specify the password for connecting to the PostgreSQL database.
7. **-dp 127.0.0.1:5433:5432:** This option specifies the port mapping for the container. It maps port 5432 on the container to port 5433 on the host machine (127.0.0.1). The -d flag tells Docker to run the container in detached mode (in the background), and the -p flag specifies the port mapping.
8. **pyrosandro/boogle-auth-db-image:0.0.1-SNAPSHOT:** This is the name of the Docker image to use for creating the container. It specifies the image "pyrosandro/boogle-auth-db-image" with the tag "0.0.1-SNAPSHOT".

### Install liquibase scripts

Once the db is installed, you can run your liquibase scripts by going into liquibase folder and run the following command:

```
mvn install -Pliquibase
```

Note: if you need to rollback your scripts, run the following command (in the example, we rollback the last 2 scripts from master.xml):

```
mvn clean -Pliquibase -Dliquibase.rollbackCount=2
```

### Run app docker container

To run a docker app container, run the following command and populate the variables as needed.

```
docker run --name boogle-auth --network=boogle-network -e "SPRING_CONFIG_ADDITIONAL_LOCATION=/config/external-props.yml" -v C:\Users\PyroSandro\Desktop\PublicRepos\boogle-extra\auth-external-props.yml:/config/external-props.yml -dp 127.0.0.1:8081:8081 pyrosandro/boogle-auth-image:0.0.1-SNAPSHOT
```

Command explanation:
1. **docker run:** This is the command used to run a Docker container.
2. **--name boogle-auth:** This option sets the name of the container to "boogle-auth". The --name flag allows you to assign a custom name to the container instead of Docker generating a random one.
3. **--network=boogle-network:** This option specifies the network to which the container should be attached. It connects the container to the Docker network named "boogle-network".
4. **-e "SPRING_CONFIG_ADDITIONAL_LOCATION=/config/external-props.yml":** This option sets an environment variable within the container. It defines an additional location for Spring configuration properties (external-props.yml). This environment variable allows the application inside the container to load configuration from an external file.
5. **-v C:\Users\PyroSandro\Desktop\PublicRepos\boogle-extra\auth-external-props.yml:/config/external-props.yml:** This option mounts a volume from the host machine to the container. It maps the local file external-props.yml located on the host machine's desktop (C:\Users\PyroSandro\Desktop\PublicRepos\boogle-extra\auth-external-props.yml) to the container's /config/external-props.yml path. This volume mounting allows the containerized application to access configuration files from the host machine.
6. **-dp 127.0.0.1:8081:8081:** This option specifies the port mapping for the container. It maps port 8081 on the container to port 8081 on the host machine (127.0.0.1). The -d flag runs the container in detached mode (in the background), and the -p flag specifies the port mapping.
7. **pyrosandro/boogle-auth-image:0.0.1-SNAPSHOT:** This part of the command specifies the Docker image to use for creating the container. It specifies the image "pyrosandro/boogle-auth-image" with the tag "0.0.1-SNAPSHOT".

Note: The external-props.yml file should contain the values of the variables needed in application.yml file. For an example, you can see the file application-localdev.yml 