// The page for the people she has chosen to tell. It connects straight to the SpacetimeDB
// module and subscribes to three views; the module decides what this identity may see.
import React from 'react';
import ReactDOM from 'react-dom/client';
import { SpacetimeDBProvider } from 'spacetimedb/react';
import { DbConnection } from './module_bindings';
import App from './App';

const URI = import.meta.env.VITE_SPACETIME_URL ?? 'http://127.0.0.1:3000';
const DATABASE = import.meta.env.VITE_SPACETIME_DB ?? 'eldershield';
const TOKEN_KEY = 'eldershield-family-token';

// The identity is the key to her alerts: once a code is used, it is bound to this identity, so
// the token is kept in this browser and reused on every visit.
let saved: string | undefined;
try { saved = localStorage.getItem(TOKEN_KEY) ?? undefined; } catch { /* private window */ }

const connectionBuilder = DbConnection.builder()
  .withUri(URI)
  .withDatabaseName(DATABASE)
  .withToken(saved)
  .withAutomaticReconnect({ minDelayMs: 1000, maxDelayMs: 10000 })   // the database may restart; her alerts come back
  .onConnect((_conn, _identity, token) => {
    try { localStorage.setItem(TOKEN_KEY, token); } catch { /* fine */ }
  });

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <SpacetimeDBProvider connectionBuilder={connectionBuilder}>
      <App />
    </SpacetimeDBProvider>
  </React.StrictMode>
);
