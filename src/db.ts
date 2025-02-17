import { MongoClient, Db } from 'mongodb';

const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017';

const mongo = new MongoClient(MONGO_URL);

let db: Db | null = null;

export async function mongo_connect() {
    await mongo.connect();
    db = mongo.db('accounting');
    console.log('Connected to mongodb');
}

/**
 * Log a request to the database
 * @param {*} request 
 */
export function logRequest(request) {
    db?.collection('requests').insertOne(request);
}

/**
 * Count the number of requests made by each user 
 * @returns {Promise<import('mongodb').Cursor>}
 
 */
export function countRequests() {
    return db?.collection('requests')
        .aggregate([
            { $project: { user: 1, affiliations: "$user.affiliations" } },
            { $group: { _id: "$user.email", affiliations: { $mergeObjects: "$affiliations" }, count: { $count: {} } } },
            { $sort: { count: -1 } }])
        .toArray();
}
