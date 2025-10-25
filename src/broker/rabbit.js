import amqp from "amqplib";
import config from "../config/config.js";

let channel, connection;

export const connect = async () => {
  connection = await amqp.connect(config.RABBITMQ_URI);
  channel = await connection.createChannel();
  console.log("🐰Connected to RabbitMQ");
};

export const publishMessage = async (queueName, message) => {
  if (!channel) {
    await connect();
  }
  await channel.assertQueue(queueName, { durable: true });
  channel.sendToQueue(queueName, Buffer.from(JSON.stringify(message)), { persistent: true });
  console.log(`Message sent to queue: ${queueName}`);
};
