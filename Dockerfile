# Stage 1: Build with Maven builder image
FROM maven:3.8.6-openjdk-21-slim as build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

# Stage 2: Create the final Docker image
FROM openjdk:21-jdk-slim

WORKDIR /app

COPY --from=build /app/target/dashboard-spring-0.0.1-SNAPSHOT.jar /app/app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]
