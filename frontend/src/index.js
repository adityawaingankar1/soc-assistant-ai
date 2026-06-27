import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/App.css';

// Polyfill for uuid in older browsers
import { v4 as uuidv4 } from 'uuid';
window.generateId = uuidv4;

const root = ReactDOM.createRoot(document.getElementById('root'));

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);