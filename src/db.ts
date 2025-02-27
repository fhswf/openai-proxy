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
            // Umwandlung der _id-Struktur zum Vereinfachen der nächsten Gruppierung
            {
                $project: {
                    year: "$_id.year",
                    month: "$_id.month",
                    affiliation: "$_id.affiliation",
                    count: 1,
                    _id: 0
                }
            },
            // Zweite Gruppierungsstufe nach Jahr und Monat, wobei die Ergebnisse je Affiliation gesammelt werden
            {
                $group: {
                    _id: {
                        year: "$year",
                        month: "$month"
                    },
                    affiliations: {
                        $push: {
                            affiliation: "$affiliation",
                            count: "$count"
                        }
                    }
                }
            },
            // Finalisierung der Struktur: Gruppierung nach Jahr und Anordnung der Monate je Jahr
            {
                $group: {
                    _id: "$_id.year",
                    months: {
                        $push: {
                            month: "$_id.month",
                            affiliations: "$affiliations"
                        }
                    }
                }
            },
            // Sortieren der Ergebnisse, zunächst nach Jahr dann innerhalb der Jahre nach Monaten
            {
                $sort: { "_id": 1, "months.month": 1 }
            }
        ])
        .toArray();
}
