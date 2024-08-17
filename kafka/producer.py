from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers='localhost:9092')

for i in range(15):
    message = f"Message {i + 1}"
    producer.send('example-topic', message.encode('utf-8'))
    print(f"Sent: {message}")

producer.flush()
producer.close()
