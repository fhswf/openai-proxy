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
            {
                $project: {
                    affiliations: { $objectToArray: "$user.affiliations" },
                    month: { $month: { $toDate: "$date" } },
                    year: { $year: { $toDate: "$date" } },
                }
            },
            {
                $unwind: "$affiliations"
            },
            {
                $group: {
                    _id: {
                        month: "$month",
                        year: "$year",
                        affiliation: "$affiliations.k"
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { "_id.year": 1, "_id.month": 1, count: -1 }
            }
        ])
        .toArray();
}
