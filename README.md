# vanillaentrademo

### This app was created to demonstrate Microsoft Entra ID (aka "Azure AD") 

1. Make sure to set proxies if required to reach microsoft.com
```
export _JAVA_OPTIONS=\
-Dhttps.proxyHost=myproxy.company.com \
-Dhttps.proxyPort=8080 \
-Dhttps.nonProxyHosts="localhost|127.0.0.0/8|*.company.com" \
-Dhttp.proxyHost=myproxy.company.com \
-Dhttp.proxyPort=8080 \
-Dhttps.nonProxyHosts="localhost|127.0.0.0/8|*.company.com"
