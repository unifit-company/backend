#Build stage: compila o projeto com Maven
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app

#Docker exige origem e destino
COPY pom.xml .

RUN mvn dependency:go-offline

COPY src ./src

RUN mvn clean package -DskipTests

#Runtime stage: imagem final, mais leve, só com o JAR e o JRE
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]