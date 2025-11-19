FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Seoul /etc/localtime && \
    echo "Asia/Seoul" > /etc/timezone

ENV TZ=Asia/Seoul

WORKDIR /app
COPY target/*.jar app.jar

CMD ["java", "-Duser.timezone=Asia/Seoul", "-jar", "app.jar"]