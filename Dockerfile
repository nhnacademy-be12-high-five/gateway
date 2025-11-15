# 각자 프로젝트 루트 파일
# 1. JDK 21이 포함된 베이스 이미지 사용
FROM openjdk:21-jre-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. CI 3번 스텝에서 빌드된 .jar 파일을 컨테이너로 복사
# (이름을 'app.jar'로 통일하면 실행하기 편합니다)
COPY target/*.jar app.jar

# 4. 컨테이너가 시작될 때 이 명령어를 실행
CMD ["java", "-jar", "app.jar"]