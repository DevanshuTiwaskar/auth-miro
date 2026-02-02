import amqp from "amqplib";
import config from "../config/config.js";

let channel;
let queueName;

export const connectRabbit = async (serviceQueue) => {
  const connection = await amqp.connect(config.RABBITMQ_URI);
  channel = await connection.createChannel();

  await channel.assertExchange("app.events", "topic", { durable: true });

  const q = await channel.assertQueue(serviceQueue, { durable: true });
  queueName = q.queue;

  await channel.bindQueue(queueName, "app.events", "#");

  console.log(`🐰 Rabbit ready for ${queueName}`);
};

export const publishEvent = async (routingKey, message) => {
  if (!channel) {
    console.log("❌ Rabbit channel not ready. Event not sent:", routingKey);
    return;
  }

  channel.publish(
    "app.events",
    routingKey,
    Buffer.from(JSON.stringify(message))
  );

  console.log("📤 Event published:", routingKey);
};


export const consumeEvents = (callback) => {
  channel.consume(
    queueName,   // ✅ VERY IMPORTANT
    (msg) => {
      const data = JSON.parse(msg.content.toString());
      callback(data, msg.fields.routingKey);
      channel.ack(msg);
    }
  );
};
