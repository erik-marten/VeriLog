@echo off
rem Run the Java build using its existing Gradle wrapper.
call "%~dp0VeriLogJava\gradlew.bat" --project-dir "%~dp0VeriLogJava" %*
exit /b %errorlevel%
