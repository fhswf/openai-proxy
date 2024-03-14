import { MongoClient } from 'mongodb';

const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017';

const mongo = new MongoClient(MONGO_URL, { useUnifiedTopology: true });

let db;

export async function mongo_connect() {
    await mongo.connect();
    db = mongo.db('accounting');
    console.log('Connected to mongodb');
}

export function logRequest(request) {
    db.collection('requests').insertOne(request);
}