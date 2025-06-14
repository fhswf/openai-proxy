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
    if (!db) {
        return Promise.resolve()
    }
    return db.collection('requests')
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
                $project: {
                    scope: "$affiliations.k",
                    roles: "$affiliations.v",
                    month: 1,
                    year: 1
                }
            },
            {
                $unwind: "$roles"
            },
            {
                $facet: {
                    byScope: [
                        {
                            $match: {
                                roles: "member"
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    year: "$year",
                                    month: "$month",
                                    scope: "$scope"
                                },
                                count: { $sum: 1 }
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    year: "$_id.year",
                                    month: "$_id.month"
                                },
                                scopes: {
                                    $push: {
                                        scope: "$_id.scope",
                                        count: "$count"
                                    }
                                }
                            }
                        },
                        {
                            $group: {
                                _id: "$_id.year",
                                months: {
                                    $push: {
                                        month: "$_id.month",
                                        scopes: "$scopes"
                                    }
                                }
                            }
                        },
                        {
                            $sort: { "_id": 1, "months.month": 1 }
                        }
                    ],
                    byRole: [
                        {
                            $match: {
                                scope: "fh-swf.de"
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    year: "$year",
                                    month: "$month",
                                    role: "$roles"
                                },
                                count: { $sum: 1 }
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    year: "$_id.year",
                                    month: "$_id.month"
                                },
                                roles: {
                                    $push: {
                                        role: "$_id.role",
                                        count: "$count"
                                    }
                                }
                            }
                        },
                        {
                            $group: {
                                _id: "$_id.year",
                                months: {
                                    $push: {
                                        month: "$_id.month",
                                        roles: "$roles"
                                    }
                                }
                            }
                        },
                        {
                            $sort: { "_id": 1, "months.month": 1 }
                        }
                    ]
                }
            }
        ])
        .toArray();
}
