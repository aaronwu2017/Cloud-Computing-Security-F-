FROM python
RUN mkdir /app
COPY app.py /app/
WORKDIR /app
RUN pip install flask
#EXPOSE 5000
#EXPOSE 8080
ENV FLASK_APP=app.py
#CMD flask run --host=0.0.0.0
CMD python app.py