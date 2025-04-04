import admin from 'firebase-admin';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Read the service account key file
const serviceAccount = JSON.parse(
    readFileSync(join(__dirname, 'serviceAccountKey.json'))
);

// Initialize Firebase Admin
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://milkmaster-ee693-default-rtdb.firebaseio.com"
});

export const database = admin.database();