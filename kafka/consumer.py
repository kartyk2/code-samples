from kafka import KafkaConsumer

consumer = KafkaConsumer(
    'example-topic',
    bootstrap_servers='localhost:9092',
    auto_offset_reset='earliest',
    group_id='example-group'
)

for message in consumer:
    print(f"Received message: {message.value.decode('utf-8')}")
