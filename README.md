[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/jbsouthe/AppDynamics-SSL-Certificate-Agent_Plugin)

## Theory of operation

This plugin will watch for low level SSL certificate operations and for any that the JVM is using, it will check the expiration and do a couple of things

- It will create a custom metric for each certificate and create a countdown of the number of days until expiration, this can be used in dashboards: "SSL Certificates|" + subject + "|Days To Expiration"
- If days to expiration is <= 2 then it will error the Business Transaction connecting to the backend and alert that the certificate is about to expire, as well as create an "APPLICATION_ERROR" event of level ERROR
- Else, if the expiration is <= 14 days it will only send an event of "APPLICATION_ERROR", level WARNING that expiration is coming

This is designed to be very noisy so that a customer of a service that is about to experience errors in SSL certificate checking will be aware that something is about to go very wrong.
Please let me know if anything more is needed. I will explore making these thresholds and behaviors configurable via node properties in the future.

## Required

- Agent version 22.1+
- Java 8


## Deployment steps

- Copy Agent Plugin Jar file under < agent-install-dir >/ver.x.x.x.x/sdk-plugins

