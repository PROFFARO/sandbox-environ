import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import Submit from './pages/Submit';
import AnalysisReport from './pages/AnalysisReport';
import History from './pages/History';
import Policies from './pages/Policies';
import './index.css';

export default function App() {
  return (
    <Router>
      <div className="app-layout">
        <Sidebar />
        <div className="main-content">
          <Header />
          <div className="page-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/submit" element={<Submit />} />
              <Route path="/report/:id" element={<AnalysisReport />} />
              <Route path="/history" element={<History />} />
              <Route path="/policies" element={<Policies />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}
