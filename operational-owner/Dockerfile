FROM eclipse-temurin:21-jre
WORKDIR /app
COPY target/gateway-operational-owner-1.0.0-SNAPSHOT.jar /app/owner.jar
USER 10001:10001
EXPOSE 8081
ENTRYPOINT ["java","-jar","/app/owner.jar"]
