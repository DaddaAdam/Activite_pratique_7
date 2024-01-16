FROM openjdk:21-oracle
WORKDIR /app
COPY target/*.jar  app.jar
ENTRYPOINT ["java","-jar", "app.jar"]