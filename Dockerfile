FROM openjdk:15
VOLUME /tmp
EXPOSE 8090
ADD ./target/app-gateway-0.0.1-SNAPSHOT.jar gateway.jar
ENTRYPOINT ["java","-jar","/gateway.jar"]