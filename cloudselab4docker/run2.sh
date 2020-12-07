docker build -t lab4:latest .

docker run -d --name=bonus -p 0:8080 lab4
echo -n "Your application is now available at http://localhost:" ; docker port bonus | rev |cut -c1-5 |rev