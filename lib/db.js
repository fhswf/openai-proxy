import { MongoClient } from 'mongodb';

const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017';

const mongo = new MongoClient(MONGO_URL, { useUnifiedTopology: true });

export async function mongo_connect() {
    await mongo.connect();
    console.log('Connected to mongodb');
}