# authserver

[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Simple backend app [Spring Boot](http://projects.spring.io/spring-boot/) for generate JWT in order to authorize 
request in another application.

Take a look at this repository [![repository](https://img.shields.io/badge/Java-Spring%20Boot-blue)](https://github.com/jijimenezf/boot-security?branch=main)

## Requirements

For building and running the application you need:

- [![JDK 1.8](https://img.shields.io/badge/Spring%20Boot-orange)](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
- [![Maven 3](https://img.shields.io/badge/Maven%20Boot-yellow)](https://maven.apache.org)

## Running the application locally

There are several ways to run a Spring Boot application on your local machine. One way is to execute the `main` method in the `com.fullstack.contactapi.Application` class from your IDE.

Alternatively you can use the [Spring Boot Maven plugin](https://docs.spring.io/spring-boot/docs/current/reference/html/build-tool-plugins-maven-plugin.html) like so:

```shell
mvn spring-boot:run
or
./mvnw spring-boot:run
```

## Credits
This application is based on an idea developed by Dan Vega https://github.com/danvega/jwt
in order to produce valid JWT.

## Features
The idea is to authenticate a user first then generate a valid JWT that could be used for authorizing subsequent requests.



## Copyright

Released under the Apache License 2.0. See the [LICENSE](https://github.com/codecentric/springboot-sample-app/blob/master/LICENSE) file.