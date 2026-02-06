import React, { useState, useCallback } from "react";
import axios from "axios";
import {
	Container,
	Typography,
	Button,
	Switch,
	FormControlLabel,
	TextField,
	Box,
	Paper,
	Divider,
	Card,
	CardMedia,
	CardContent,
	CardActions,
	Grid,
	CircularProgress,
	Snackbar,
	Alert,
	LinearProgress,
	IconButton,
	Tooltip,
	Fade,
	Stepper,
	Step,
	StepLabel,
	Accordion,
	AccordionSummary,
	AccordionDetails,
	Chip,
	Table,
	TableBody,
	TableCell,
	TableContainer,
	TableHead,
	TableRow,
} from "@mui/material";
import { styled, ThemeProvider, createTheme } from "@mui/material/styles";
import { Bar, Pie } from "react-chartjs-2";
import {
	Chart as ChartJS,
	ArcElement,
	BarElement,
	CategoryScale,
	LinearScale,
	Tooltip as ChartTooltip,
	Legend,
} from "chart.js";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import DarkModeIcon from "@mui/icons-material/DarkMode";
import LightModeIcon from "@mui/icons-material/LightMode";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import AnalyticsIcon from "@mui/icons-material/Analytics";
import EditIcon from "@mui/icons-material/Edit";
import BuildIcon from "@mui/icons-material/Build";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LinkIcon from "@mui/icons-material/Link";
import CodeIcon from "@mui/icons-material/Code";
import StorageIcon from "@mui/icons-material/Storage";
import "./styles/App.css";

// Register Chart.js components
ChartJS.register(
	ArcElement,
	BarElement,
	CategoryScale,
	LinearScale,
	ChartTooltip,
	Legend,
);

// Wizard Steps Configuration
const wizardSteps = [
	{
		label: "Upload",
		icon: <CloudUploadIcon />,
		description: "Upload and decompile APK",
	},
	{
		label: "Analyze",
		icon: <AnalyticsIcon />,
		description: "Review APK statistics and security scan",
	},
	{
		label: "Modify",
		icon: <EditIcon />,
		description: "Edit icons, assets, permissions",
	},
	{
		label: "Rebuild",
		icon: <BuildIcon />,
		description: "Save manifest and rebuild APK",
	},
	{
		label: "Complete",
		icon: <CheckCircleIcon />,
		description: "Download modified APK",
	},
];

// Custom styled components
const GlassPaper = styled(Paper)(({ theme }) => ({
	background: "rgba(255, 255, 255, 0.05)",
	backdropFilter: "blur(10px)",
	border: "1px solid rgba(255, 255, 255, 0.1)",
	boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
	borderRadius: "12px",
}));

const NeonButton = styled(Button)(({ theme }) => ({
	background: "linear-gradient(45deg, #00e676, #00c4b4)",
	border: "none",
	padding: "10px 24px",
	borderRadius: "8px",
	textTransform: "uppercase",
	fontWeight: "bold",
	"&:hover": {
		background: "linear-gradient(45deg, #00c4b4, #00e676)",
		boxShadow: "0 0 15px rgba(0, 230, 118, 0.5)",
	},
}));

const LoadingOverlay = styled(Box)(({ theme }) => ({
	position: "fixed",
	top: 0,
	left: 0,
	width: "100%",
	height: "100%",
	backgroundColor: "rgba(0, 0, 0, 0.5)",
	display: "flex",
	justifyContent: "center",
	alignItems: "center",
	zIndex: 1000,
}));

// Drag & Drop Zone
const DropZone = styled(Paper)(({ theme, isdragover }) => ({
	border: isdragover
		? "2px dashed #00e676"
		: "2px dashed rgba(255, 255, 255, 0.3)",
	borderRadius: "12px",
	padding: "40px",
	textAlign: "center",
	cursor: "pointer",
	transition: "all 0.3s ease",
	background: isdragover
		? "rgba(0, 230, 118, 0.1)"
		: "rgba(255, 255, 255, 0.05)",
	"&:hover": {
		borderColor: "#00e676",
		background: "rgba(0, 230, 118, 0.1)",
	},
}));

// Progress Card Component
const ProgressCard = ({ label, value, icon: Icon }) => (
	<Card
		sx={{
			background: "rgba(255, 255, 255, 0.03)",
			border: "1px solid rgba(255, 255, 255, 0.1)",
			borderRadius: "12px",
			padding: "16px",
			textAlign: "center",
		}}
	>
		<CardContent>
			{Icon && (
				<Box sx={{ mb: 1 }}>
					<Icon sx={{ color: "#00e676", fontSize: 32 }} />
				</Box>
			)}
			<Typography
				variant="h6"
				sx={{
					color: "#00e676",
					fontWeight: "bold",
				}}
			>
				{label}
			</Typography>
			<Typography
				variant="h4"
				sx={{
					color: "#fff",
					fontWeight: "bold",
					letterSpacing: "2px",
				}}
			>
				{typeof value === "number" ? value.toLocaleString() : value}
			</Typography>
		</CardContent>
	</Card>
);

// Security Risk Badge Component
const RiskBadge = ({ risk }) => {
	const colors = {
		CRITICAL: { bg: "#ff1744", icon: <ErrorIcon /> },
		HIGH: { bg: "#ff5722", icon: <WarningIcon /> },
		MEDIUM: { bg: "#ffc107", icon: <InfoIcon /> },
		LOW: { bg: "#4caf50", icon: <CheckCircleIcon /> },
	};

	const config = colors[risk] || colors.LOW;

	return (
		<Chip
			icon={config.icon}
			label={risk}
			sx={{
				backgroundColor: config.bg,
				color: "#fff",
				fontWeight: "bold",
			}}
		/>
	);
};

// Toast Notification Component
const Toast = ({ open, message, severity, onClose }) => (
	<Snackbar
		open={open}
		autoHideDuration={4000}
		onClose={onClose}
		anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
	>
		<Alert
			onClose={onClose}
			severity={severity}
			variant="filled"
			sx={{
				width: "100%",
				fontWeight: "bold",
			}}
		>
			{message}
		</Alert>
	</Snackbar>
);

// Custom Wizard Stepper Component
const WizardStepper = ({ activeStep, completed }) => (
	<Box sx={{ mb: 4 }}>
		<Stepper
			activeStep={activeStep}
			alternativeLabel
			sx={{
				"& .MuiStepLabel-label": {
					color: "rgba(255, 255, 255, 0.7)",
					fontSize: "12px",
				},
				"& .MuiStepLabel-label.Mui-active": {
					color: "#00e676",
					fontWeight: "bold",
				},
				"& .MuiStepLabel-label.Mui-completed": {
					color: "#00e676",
				},
				"& .MuiStepIcon-root": {
					color: "rgba(255, 255, 255, 0.3)",
				},
				"& .MuiStepIcon-root.Mui-active": {
					color: "#00e676",
				},
				"& .MuiStepIcon-root.Mui-completed": {
					color: "#00e676",
				},
			}}
		>
			{wizardSteps.map((step, index) => (
				<Step key={step.label} completed={completed[index]}>
					<StepLabel
						icon={
							completed[index] ? (
								<CheckCircleIcon sx={{ color: "#00e676" }} />
							) : (
								step.icon
							)
						}
					>
						<Typography
							variant="caption"
							sx={{
								display: "block",
								mt: 1,
								fontWeight: index === activeStep ? "bold" : "normal",
								color: index === activeStep ? "#00e676" : "inherit",
							}}
						>
							{step.label}
						</Typography>
					</StepLabel>
				</Step>
			))}
		</Stepper>
		<Typography
			variant="body2"
			sx={{
				textAlign: "center",
				mt: 2,
				color: "rgba(255, 255, 255, 0.7)",
			}}
		>
			{wizardSteps[activeStep]?.description}
		</Typography>
	</Box>
);

// Security Findings Display Component
const SecurityFindings = ({ scanResults }) => {
	if (!scanResults) return null;

	const {
		scan_summary,
		smali_findings,
		manifest_findings,
		all_urls,
		recommendations,
	} = scanResults;

	const totalFindings =
		scan_summary.critical_count +
		scan_summary.high_count +
		scan_summary.medium_count +
		scan_summary.low_count;

	const getRiskColor = (risk) => {
		switch (risk) {
			case "CRITICAL":
				return "#ff1744";
			case "HIGH":
				return "#ff5722";
			case "MEDIUM":
				return "#ffc107";
			default:
				return "#4caf50";
		}
	};

	return (
		<GlassPaper sx={{ p: 3, mb: 4 }}>
			<Box sx={{ display: "flex", alignItems: "center", mb: 3 }}>
				<SecurityIcon sx={{ color: "#00e676", fontSize: 32, mr: 2 }} />
				<Typography variant="h5" sx={{ color: "#00e676", fontWeight: "bold" }}>
					Security Analysis Results
				</Typography>
			</Box>

			{/* Summary Cards */}
			<Grid container spacing={2} sx={{ mb: 4 }}>
				<Grid item xs={6} sm={3}>
					<Card
						sx={{
							background: "rgba(255, 23, 68, 0.2)",
							border: "1px solid rgba(255, 23, 68, 0.5)",
							borderRadius: "12px",
							textAlign: "center",
						}}
					>
						<CardContent>
							<Typography
								variant="h4"
								sx={{ color: "#ff1744", fontWeight: "bold" }}
							>
								{scan_summary.critical_count}
							</Typography>
							<Typography variant="body2" sx={{ color: "#ff1744" }}>
								Critical
							</Typography>
						</CardContent>
					</Card>
				</Grid>
				<Grid item xs={6} sm={3}>
					<Card
						sx={{
							background: "rgba(255, 87, 34, 0.2)",
							border: "1px solid rgba(255, 87, 34, 0.5)",
							borderRadius: "12px",
							textAlign: "center",
						}}
					>
						<CardContent>
							<Typography
								variant="h4"
								sx={{ color: "#ff5722", fontWeight: "bold" }}
							>
								{scan_summary.high_count}
							</Typography>
							<Typography variant="body2" sx={{ color: "#ff5722" }}>
								High
							</Typography>
						</CardContent>
					</Card>
				</Grid>
				<Grid item xs={6} sm={3}>
					<Card
						sx={{
							background: "rgba(255, 193, 7, 0.2)",
							border: "1px solid rgba(255, 193, 7, 0.5)",
							borderRadius: "12px",
							textAlign: "center",
						}}
					>
						<CardContent>
							<Typography
								variant="h4"
								sx={{ color: "#ffc107", fontWeight: "bold" }}
							>
								{scan_summary.medium_count}
							</Typography>
							<Typography variant="body2" sx={{ color: "#ffc107" }}>
								Medium
							</Typography>
						</CardContent>
					</Card>
				</Grid>
				<Grid item xs={6} sm={3}>
					<Card
						sx={{
							background: "rgba(76, 175, 80, 0.2)",
							border: "1px solid rgba(76, 175, 80, 0.5)",
							borderRadius: "12px",
							textAlign: "center",
						}}
					>
						<CardContent>
							<Typography
								variant="h4"
								sx={{ color: "#4caf50", fontWeight: "bold" }}
							>
								{scan_summary.low_count}
							</Typography>
							<Typography variant="body2" sx={{ color: "#4caf50" }}>
								Low
							</Typography>
						</CardContent>
					</Card>
				</Grid>
			</Grid>

			{/* URLs Found */}
			{all_urls && all_urls.length > 0 && (
				<Accordion sx={{ mb: 2 }}>
					<AccordionSummary expandIcon={<ExpandMoreIcon />}>
						<Box sx={{ display: "flex", alignItems: "center" }}>
							<LinkIcon sx={{ color: "#00e676", mr: 1 }} />
							<Typography variant="h6" sx={{ color: "#fff" }}>
								APIs & URLs Found ({all_urls.length})
							</Typography>
						</Box>
					</AccordionSummary>
					<AccordionDetails>
						<TableContainer>
							<Table size="small">
								<TableHead>
									<TableRow>
										<TableCell sx={{ color: "#00e676" }}>URL</TableCell>
										<TableCell sx={{ color: "#00e676" }}>Type</TableCell>
										<TableCell sx={{ color: "#00e676" }}>Risk</TableCell>
									</TableRow>
								</TableHead>
								<TableBody>
									{all_urls.map((url, index) => (
										<TableRow key={index}>
											<TableCell sx={{ color: "#fff", wordBreak: "break-all" }}>
												{url.url}
											</TableCell>
											<TableCell sx={{ color: "#fff" }}>{url.type}</TableCell>
											<TableCell>
												<Chip
													label={url.risk}
													size="small"
													sx={{
														backgroundColor:
															url.risk === "HIGH" ? "#ff5722" : "#4caf50",
														color: "#fff",
													}}
												/>
											</TableCell>
										</TableRow>
									))}
								</TableBody>
							</Table>
						</TableContainer>
					</AccordionDetails>
				</Accordion>
			)}

			{/* Hardcoded Secrets */}
			{smali_findings.hardcoded_secrets &&
				smali_findings.hardcoded_secrets.length > 0 && (
					<Accordion sx={{ mb: 2 }}>
						<AccordionSummary expandIcon={<ExpandMoreIcon />}>
							<Box sx={{ display: "flex", alignItems: "center" }}>
								<ErrorIcon sx={{ color: "#ff1744", mr: 1 }} />
								<Typography variant="h6" sx={{ color: "#fff" }}>
									Hardcoded Secrets ({smali_findings.hardcoded_secrets.length})
								</Typography>
							</Box>
						</AccordionSummary>
						<AccordionDetails>
							{smali_findings.hardcoded_secrets.map((secret, index) => (
								<Card
									key={index}
									sx={{
										mb: 2,
										background: "rgba(255, 23, 68, 0.1)",
										border: "1px solid rgba(255, 23, 68, 0.3)",
									}}
								>
									<CardContent>
										<Box
											sx={{
												display: "flex",
												justifyContent: "space-between",
												mb: 1,
											}}
										>
											<Typography variant="subtitle1" sx={{ color: "#ff1744" }}>
												{secret.type}
											</Typography>
											<RiskBadge risk={secret.risk} />
										</Box>
										<Typography
											variant="body2"
											sx={{
												color: "rgba(255,255,255,0.7)",
												fontFamily: "monospace",
												wordBreak: "break-all",
											}}
										>
											{secret.match}
										</Typography>
										<Typography
											variant="body2"
											sx={{ color: "#ffc107", mt: 1 }}
										>
											Recommendation: {secret.recommendation}
										</Typography>
									</CardContent>
								</Card>
							))}
						</AccordionDetails>
					</Accordion>
				)}

			{/* Vulnerable Libraries */}
			{smali_findings.vulnerable_libraries &&
				smali_findings.vulnerable_libraries.length > 0 && (
					<Accordion sx={{ mb: 2 }}>
						<AccordionSummary expandIcon={<ExpandMoreIcon />}>
							<Box sx={{ display: "flex", alignItems: "center" }}>
								<StorageIcon sx={{ color: "#ff5722", mr: 1 }} />
								<Typography variant="h6" sx={{ color: "#fff" }}>
									Vulnerable Libraries (
									{smali_findings.vulnerable_libraries.length})
								</Typography>
							</Box>
						</AccordionSummary>
						<AccordionDetails>
							<TableContainer>
								<Table size="small">
									<TableHead>
										<TableRow>
											<TableCell sx={{ color: "#00e676" }}>Library</TableCell>
											<TableCell sx={{ color: "#00e676" }}>CVE</TableCell>
											<TableCell sx={{ color: "#00e676" }}>Risk</TableCell>
										</TableRow>
									</TableHead>
									<TableBody>
										{smali_findings.vulnerable_libraries.map((lib, index) => (
											<TableRow key={index}>
												<TableCell sx={{ color: "#fff" }}>
													{lib.library}
												</TableCell>
												<TableCell sx={{ color: "#ff1744" }}>
													{lib.cve}
												</TableCell>
												<TableCell>
													<RiskBadge risk={lib.risk} />
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							</TableContainer>
						</AccordionDetails>
					</Accordion>
				)}

			{/* WebView Issues */}
			{smali_findings.webview_issues &&
				smali_findings.webview_issues.length > 0 && (
					<Accordion sx={{ mb: 2 }}>
						<AccordionSummary expandIcon={<ExpandMoreIcon />}>
							<Box sx={{ display: "flex", alignItems: "center" }}>
								<CodeIcon sx={{ color: "#ffc107", mr: 1 }} />
								<Typography variant="h6" sx={{ color: "#fff" }}>
									WebView Issues ({smali_findings.webview_issues.length})
								</Typography>
							</Box>
						</AccordionSummary>
						<AccordionDetails>
							{smali_findings.webview_issues.map((issue, index) => (
								<Card
									key={index}
									sx={{
										mb: 2,
										background: "rgba(255, 193, 7, 0.1)",
										border: "1px solid rgba(255, 193, 7, 0.3)",
									}}
								>
									<CardContent>
										<Box
											sx={{
												display: "flex",
												justifyContent: "space-between",
												mb: 1,
											}}
										>
											<Typography variant="subtitle1" sx={{ color: "#ffc107" }}>
												{issue.pattern}
											</Typography>
											<RiskBadge risk={issue.risk} />
										</Box>
										<Typography
											variant="body2"
											sx={{ color: "rgba(255,255,255,0.7)" }}
										>
											{issue.description}
										</Typography>
									</CardContent>
								</Card>
							))}
						</AccordionDetails>
					</Accordion>
				)}

			{/* Manifest Issues */}
			{manifest_findings.exported_components &&
				manifest_findings.exported_components.length > 0 && (
					<Accordion sx={{ mb: 2 }}>
						<AccordionSummary expandIcon={<ExpandMoreIcon />}>
							<Box sx={{ display: "flex", alignItems: "center" }}>
								<SecurityIcon sx={{ color: "#ff5722", mr: 1 }} />
								<Typography variant="h6" sx={{ color: "#fff" }}>
									Exported Components (
									{manifest_findings.exported_components.length})
								</Typography>
							</Box>
						</AccordionSummary>
						<AccordionDetails>
							{manifest_findings.exported_components.map((comp, index) => (
								<Card
									key={index}
									sx={{
										mb: 2,
										background: "rgba(255, 87, 34, 0.1)",
										border: "1px solid rgba(255, 87, 34, 0.3)",
									}}
								>
									<CardContent>
										<Typography variant="subtitle1" sx={{ color: "#ff5722" }}>
											{comp.component}: {comp.name}
										</Typography>
										<Typography
											variant="body2"
											sx={{ color: "rgba(255,255,255,0.7)" }}
										>
											{comp.description}
										</Typography>
									</CardContent>
								</Card>
							))}
						</AccordionDetails>
					</Accordion>
				)}

			{/* Recommendations */}
			{recommendations && recommendations.length > 0 && (
				<Accordion defaultExpanded>
					<AccordionSummary expandIcon={<ExpandMoreIcon />}>
						<Box sx={{ display: "flex", alignItems: "center" }}>
							<CheckCircleIcon sx={{ color: "#00e676", mr: 1 }} />
							<Typography variant="h6" sx={{ color: "#fff" }}>
								Recommendations
							</Typography>
						</Box>
					</AccordionSummary>
					<AccordionDetails>
						{recommendations.map((rec, index) => (
							<Card
								key={index}
								sx={{
									mb: 2,
									background: "rgba(0, 230, 118, 0.1)",
									border: "1px solid rgba(0, 230, 118, 0.3)",
								}}
							>
								<CardContent>
									<Box
										sx={{
											display: "flex",
											justifyContent: "space-between",
											mb: 1,
										}}
									>
										<Typography variant="subtitle1" sx={{ color: "#00e676" }}>
											{rec.title}
										</Typography>
										<Chip
											label={rec.priority}
											size="small"
											sx={{
												backgroundColor:
													rec.priority === "CRITICAL"
														? "#ff1744"
														: rec.priority === "HIGH"
															? "#ff5722"
															: "#4caf50",
												color: "#fff",
											}}
										/>
									</Box>
									<Typography
										variant="body2"
										sx={{ color: "rgba(255,255,255,0.7)", mb: 1 }}
									>
										{rec.description}
									</Typography>
									{rec.actions && rec.actions.length > 0 && (
										<Box component="ul" sx={{ m: 0, pl: 2 }}>
											{rec.actions.map((action, i) => (
												<li key={i}>
													<Typography
														variant="body2"
														sx={{ color: "rgba(255,255,255,0.8)" }}
													>
														{action}
													</Typography>
												</li>
											))}
										</Box>
									)}
								</CardContent>
							</Card>
						))}
					</AccordionDetails>
				</Accordion>
			)}
		</GlassPaper>
	);
};

function App() {
	const API_URL = "http://localhost:5000";

	// Wizard state
	const [activeStep, setActiveStep] = useState(0);
	const [completed, setCompleted] = useState({});

	// Theme state
	const [isDarkMode, setIsDarkMode] = useState(true);

	// Toast state
	const [toast, setToast] = useState({
		open: false,
		message: "",
		severity: "success",
	});

	// Drag & Drop state
	const [isDragOver, setIsDragOver] = useState(false);
	const [uploadProgress, setUploadProgress] = useState(0);

	// Processing step state
	const [processingStep, setProcessingStep] = useState(-1);
	const processingSteps = [
		"Upload",
		"Decompile",
		"Extract Icons",
		"Extract Assets",
		"Analyze Manifest",
		"Complete",
	];

	// Security scan state
	const [securityScanResults, setSecurityScanResults] = useState(null);
	const [scanningSecurity, setScanningSecurity] = useState(false);

	// Existing state
	const [file, setFile] = useState(null);
	const [decompiledDir, setDecompiledDir] = useState("");
	const [icons, setIcons] = useState([]);
	const [assets, setAssets] = useState([]);
	const [permissions, setPermissions] = useState([]);
	const [listeners, setListeners] = useState([]);
	const [newLogo, setNewLogo] = useState(null);
	const [newAsset, setNewAsset] = useState(null);
	const [stats, setStats] = useState(null);
	const [loading, setLoading] = useState(false);

	// Wizard navigation helpers
	const handleNext = useCallback(() => {
		setCompleted((prev) => ({ ...prev, [activeStep]: true }));
		setActiveStep((prev) => prev + 1);
	}, [activeStep]);

	const handleBack = useCallback(() => {
		setActiveStep((prev) => prev - 1);
	}, []);

	const handleReset = useCallback(() => {
		setActiveStep(0);
		setCompleted({});
		setFile(null);
		setDecompiledDir("");
		setIcons([]);
		setAssets([]);
		setPermissions([]);
		setListeners([]);
		setStats(null);
		setSecurityScanResults(null);
	}, []);

	// Toast helpers
	const showToast = useCallback((message, severity = "success") => {
		setToast({ open: true, message, severity });
	}, []);

	const handleToastClose = useCallback(() => {
		setToast((prev) => ({ ...prev, open: false }));
	}, []);

	// Drag & Drop handlers
	const handleDragOver = useCallback((e) => {
		e.preventDefault();
		setIsDragOver(true);
	}, []);

	const handleDragLeave = useCallback((e) => {
		e.preventDefault();
		setIsDragOver(false);
	}, []);

	const handleDrop = useCallback(
		(e) => {
			e.preventDefault();
			setIsDragOver(false);
			const droppedFile = e.dataTransfer.files[0];
			if (droppedFile && droppedFile.name.endsWith(".apk")) {
				setFile(droppedFile);
				showToast(`File selected: ${droppedFile.name}`, "info");
			} else {
				showToast("Please drop a valid APK file", "error");
			}
		},
		[showToast],
	);

	const handleFileChange = (e) => {
		const selectedFile = e.target.files[0];
		if (selectedFile && selectedFile.name.endsWith(".apk")) {
			setFile(selectedFile);
			showToast(`File selected: ${selectedFile.name}`, "info");
		} else {
			showToast("Please select a valid APK file", "error");
		}
	};

	const handleLogoChange = (e) => setNewLogo(e.target.files[0]);
	const handleAssetChange = (e) => setNewAsset(e.target.files[0]);

	// Security Scan Function
	const runSecurityScan = async () => {
		if (!decompiledDir) {
			showToast("Please upload and decompile an APK first", "warning");
			return;
		}

		setScanningSecurity(true);
		try {
			const res = await axios.post(`${API_URL}/security-scan`, {
				decompiled_dir: decompiledDir,
			});
			setSecurityScanResults(res.data);
			showToast("Security scan completed", "success");
		} catch (err) {
			showToast(
				"Error running security scan: " +
					(err.response?.data?.error || err.message),
				"error",
			);
		} finally {
			setScanningSecurity(false);
		}
	};

	// Replace alert() with showToast()
	const replaceLogo = async (icon) => {
		if (!newLogo) {
			showToast("Please select a logo to replace with", "warning");
			return;
		}

		setProcessingStep(0);
		const formData = new FormData();
		formData.append("logo", newLogo);
		formData.append("iconPath", icon);

		try {
			setProcessingStep(1);
			const res = await axios.post(`${API_URL}/replace-logo`, formData);
			setProcessingStep(2);
			showToast(res.data.message, "success");
		} catch (err) {
			showToast(
				"Error replacing logo: " + (err.response?.data?.error || err.message),
				"error",
			);
		} finally {
			setProcessingStep(-1);
		}
	};

	const replaceAsset = async (asset) => {
		if (!newAsset) {
			showToast("Please select an asset to replace with", "warning");
			return;
		}

		setProcessingStep(0);
		const formData = new FormData();
		formData.append("asset", newAsset);
		formData.append("assetPath", asset);

		try {
			setProcessingStep(1);
			const res = await axios.post(`${API_URL}/replace-asset`, formData);
			setProcessingStep(2);
			showToast(res.data.message, "success");
		} catch (err) {
			showToast(
				"Error replacing asset: " + (err.response?.data?.error || err.message),
				"error",
			);
		} finally {
			setProcessingStep(-1);
		}
	};

	const togglePermission = (permName) => {
		setPermissions(
			permissions.map((p) =>
				p.name === permName ? { ...p, enabled: !p.enabled } : p,
			),
		);
	};

	const updateListeners = (index, value) => {
		const updatedListeners = [...listeners];
		updatedListeners[index] = value;
		setListeners(updatedListeners);
	};

	const addListener = () => {
		setListeners([...listeners, ""]);
	};

	const saveManifest = async () => {
		setProcessingStep(0);
		try {
			setProcessingStep(1);
			const res = await axios.post(`${API_URL}/save-manifest`, {
				dir: decompiledDir,
				permissions: permissions.filter((p) => p.enabled).map((p) => p.name),
				listeners,
			});
			setProcessingStep(2);
			showToast(res.data.message, "success");
		} catch (err) {
			showToast(
				"Error saving manifest: " + (err.response?.data?.error || err.message),
				"error",
			);
		} finally {
			setProcessingStep(-1);
		}
	};

	const rebuildApk = async () => {
		setProcessingStep(0);
		try {
			setProcessingStep(1);
			const res = await axios.post(
				`${API_URL}/rebuild`,
				{
					dir: decompiledDir,
				},
				{
					responseType: "blob",
				},
			);
			setProcessingStep(2);

			// Create a download link for the APK
			const url = window.URL.createObjectURL(new Blob([res.data]));
			const link = document.createElement("a");
			link.href = url;
			link.setAttribute("download", "modified.apk");
			document.body.appendChild(link);
			link.click();
			link.remove();
			setProcessingStep(3);
			showToast("APK rebuilt and downloaded successfully!", "success");
		} catch (err) {
			showToast("Error rebuilding APK: " + err.message, "error");
		} finally {
			setProcessingStep(-1);
		}
	};

	const uploadApk = async () => {
		if (!file) {
			showToast("Please upload an APK first", "warning");
			return;
		}
		setLoading(true);
		setUploadProgress(0);
		setProcessingStep(0);

		const formData = new FormData();
		formData.append("apk", file);

		try {
			// Simulate progress with interval
			const progressInterval = setInterval(() => {
				setUploadProgress((prev) => {
					if (prev >= 90) {
						clearInterval(progressInterval);
						return prev;
					}
					return prev + 10;
				});
			}, 500);

			const res = await axios.post(`${API_URL}/upload`, formData, {
				timeout: 10000000,
			});

			setUploadProgress(100);
			setProcessingStep(4);

			setDecompiledDir(res.data.decompiled_dir);
			setIcons(res.data.icons);
			setAssets(res.data.assets);
			setPermissions(
				res.data.permissions.map((perm) => ({ name: perm, enabled: true })),
			);
			setListeners(res.data.listeners);
			setStats(res.data.stats);

			clearInterval(progressInterval);
			showToast(res.data.message, "success");
			handleNext(); // Move to next step after successful upload
		} catch (err) {
			showToast(
				"Error uploading APK: " + (err.response?.data?.error || err.message),
				"error",
			);
		} finally {
			setLoading(false);
			setTimeout(() => {
				setProcessingStep(-1);
				setUploadProgress(0);
			}, 1000);
		}
	};

	const toggleTheme = () => {
		setIsDarkMode(!isDarkMode);
		showToast(
			isDarkMode ? "Switched to Light Mode" : "Switched to Dark Mode",
			"info",
		);
	};

	// Theme configuration
	const theme = createTheme({
		palette: {
			mode: isDarkMode ? "dark" : "light",
			primary: {
				main: "#00e676",
			},
			secondary: {
				main: "#00c4b4",
			},
		},
		components: {
			MuiCssBaseline: {
				styleOverrides: {
					body: {
						background: isDarkMode
							? "linear-gradient(135deg, #1a237e 0%, #120136 100%)"
							: "linear-gradient(135deg, #e8eaf6 0%, #c5cae9 100%)",
					},
				},
			},
		},
	});

	const barData = stats
		? {
				labels: [
					"Lines of Code",
					"Permissions",
					"Listeners",
					"Activities",
					"Background Workers",
					"Classes",
				],
				datasets: [
					{
						label: "APK Statistics",
						data: [
							stats.lines_of_code,
							stats.total_permissions,
							stats.total_listeners,
							stats.total_activities,
							stats.background_workers,
							stats.total_classes,
						],
						backgroundColor: "rgba(0, 230, 118, 0.7)",
						borderColor: "#00e676",
						borderWidth: 1,
					},
				],
			}
		: null;

	const pieData = stats
		? {
				labels: ["Icons", "Assets"],
				datasets: [
					{
						data: [stats.total_icons, stats.total_assets],
						backgroundColor: ["#00e676", "#00c4b4"],
						hoverBackgroundColor: ["#00d165", "#00b3a3"],
					},
				],
			}
		: null;

	// Render Step Content
	const renderStepContent = (step) => {
		switch (step) {
			case 0:
				return (
					<GlassPaper sx={{ p: 3, mb: 4 }}>
						<Typography variant="h5" sx={{ mb: 3, color: "#00e676" }}>
							Upload APK
						</Typography>

						{/* Drag & Drop Zone */}
						<DropZone
							isdragover={isDragOver}
							onDragOver={handleDragOver}
							onDragLeave={handleDragLeave}
							onDrop={handleDrop}
							onClick={() => document.getElementById("file-input").click()}
							sx={{ mb: 3 }}
						>
							<UploadFileIcon sx={{ fontSize: 64, color: "#00e676", mb: 2 }} />
							<Typography variant="h6" sx={{ mb: 1 }}>
								{file ? file.name : "Drag & Drop APK file here"}
							</Typography>
							<Typography
								variant="body2"
								sx={{ color: "rgba(255,255,255,0.7)" }}
							>
								or click to browse
							</Typography>
							<input
								id="file-input"
								type="file"
								accept=".apk"
								onChange={handleFileChange}
								style={{ display: "none" }}
							/>
						</DropZone>

						{/* Upload Progress */}
						{uploadProgress > 0 && uploadProgress < 100 && (
							<Box sx={{ mb: 3 }}>
								<Box
									sx={{
										display: "flex",
										justifyContent: "space-between",
										mb: 1,
									}}
								>
									<Typography variant="body2">Uploading...</Typography>
									<Typography variant="body2">{uploadProgress}%</Typography>
								</Box>
								<LinearProgress
									variant="determinate"
									value={uploadProgress}
									sx={{
										height: 8,
										borderRadius: 4,
										backgroundColor: "rgba(255, 255, 255, 0.1)",
										"& .MuiLinearProgress-bar": {
											background: "linear-gradient(45deg, #00e676, #00c4b4)",
										},
									}}
								/>
							</Box>
						)}

						<Button
							variant="contained"
							onClick={uploadApk}
							disabled={!file || loading}
							startIcon={<CloudUploadIcon />}
							sx={{
								background: "linear-gradient(45deg, #00e676, #00c4b4)",
								"&:hover": {
									background: "linear-gradient(45deg, #00c4b4, #00e676)",
								},
							}}
						>
							{loading ? "Processing..." : "Upload & Decompile"}
						</Button>
					</GlassPaper>
				);

			case 1:
				return stats ? (
					<>
						<GlassPaper sx={{ p: 3, mb: 4 }}>
							<Typography
								variant="h5"
								sx={{
									mb: 3,
									color: "#00e676",
									fontWeight: "bold",
									textAlign: "center",
									textTransform: "uppercase",
									letterSpacing: "2px",
								}}
							>
								APK Analysis Statistics
							</Typography>

							{/* Statistics Cards - Responsive Grid */}
							<Grid container spacing={3} sx={{ textAlign: "center" }}>
								<Grid item xs={12} sm={6} md={4}>
									<ProgressCard
										label="Lines of Code"
										value={stats.lines_of_code}
									/>
								</Grid>
								<Grid item xs={12} sm={6} md={4}>
									<ProgressCard
										label="Permissions"
										value={stats.total_permissions}
									/>
								</Grid>
								<Grid item xs={12} sm={6} md={4}>
									<ProgressCard
										label="Listeners"
										value={stats.total_listeners}
									/>
								</Grid>
								<Grid item xs={12} sm={6} md={4}>
									<ProgressCard
										label="Activities"
										value={stats.total_activities}
									/>
								</Grid>
								<Grid item xs={12} sm={6} md={4}>
									<ProgressCard
										label="Background Workers"
										value={stats.background_workers}
									/>
								</Grid>
								<Grid item xs={12} sm={6} md={4}>
									<ProgressCard label="Classes" value={stats.total_classes} />
								</Grid>
								<Grid item xs={12} sm={6} md={6}>
									<ProgressCard label="Icons" value={stats.total_icons} />
								</Grid>
								<Grid item xs={12} sm={6} md={6}>
									<ProgressCard label="Assets" value={stats.total_assets} />
								</Grid>
							</Grid>

							{/* Charts Section */}
							<Divider sx={{ my: 4, borderColor: "rgba(0, 230, 118, 0.3)" }} />

							<Grid container spacing={4}>
								<Grid item xs={12} md={6}>
									<Typography
										variant="h6"
										sx={{
											mb: 2,
											color: "#00e676",
											textAlign: "center",
										}}
									>
										Statistics Overview
									</Typography>
									{barData && (
										<Box
											sx={{
												background: "rgba(255, 255, 255, 0.05)",
												borderRadius: 2,
												p: 2,
											}}
										>
											<Bar
												data={barData}
												options={{
													responsive: true,
													maintainAspectRatio: true,
													plugins: {
														legend: {
															labels: {
																color: "#fff",
															},
														},
													},
													scales: {
														x: {
															ticks: { color: "#fff" },
															grid: { color: "rgba(255,255,255,0.1)" },
														},
														y: {
															ticks: { color: "#fff" },
															grid: { color: "rgba(255,255,255,0.1)" },
														},
													},
												}}
											/>
										</Box>
									)}
								</Grid>
								<Grid item xs={12} md={6}>
									<Typography
										variant="h6"
										sx={{
											mb: 2,
											color: "#00e676",
											textAlign: "center",
										}}
									>
										Resources Distribution
									</Typography>
									{pieData && (
										<Box
											sx={{
												background: "rgba(255, 255, 255, 0.05)",
												borderRadius: 2,
												p: 2,
												display: "flex",
												justifyContent: "center",
											}}
										>
											<div style={{ width: 300, height: 300 }}>
												<Pie
													data={pieData}
													options={{
														responsive: true,
														maintainAspectRatio: true,
														plugins: {
															legend: {
																labels: {
																	color: "#fff",
																},
															},
														},
													}}
												/>
											</div>
										</Box>
									)}
								</Grid>
							</Grid>
						</GlassPaper>

						{/* Security Scanner */}
						<GlassPaper sx={{ p: 3, mb: 4 }}>
							<Box
								sx={{
									display: "flex",
									justifyContent: "space-between",
									alignItems: "center",
									mb: 3,
								}}
							>
								<Box sx={{ display: "flex", alignItems: "center" }}>
									<SecurityIcon
										sx={{ color: "#00e676", fontSize: 32, mr: 2 }}
									/>
									<Typography
										variant="h5"
										sx={{ color: "#00e676", fontWeight: "bold" }}
									>
										Security Scanner
									</Typography>
								</Box>
								<Button
									variant="contained"
									onClick={runSecurityScan}
									disabled={scanningSecurity || !decompiledDir}
									startIcon={
										scanningSecurity ? (
											<CircularProgress size={20} />
										) : (
											<SecurityIcon />
										)
									}
									sx={{
										background: "linear-gradient(45deg, #00e676, #00c4b4)",
										"&:hover": {
											background: "linear-gradient(45deg, #00c4b4, #00e676)",
										},
									}}
								>
									{scanningSecurity ? "Scanning..." : "Run Security Scan"}
								</Button>
							</Box>

							{scanningSecurity && (
								<Box sx={{ textAlign: "center", py: 4 }}>
									<CircularProgress
										size={60}
										sx={{ color: "#00e676", mb: 2 }}
									/>
									<Typography variant="h6" sx={{ color: "#fff" }}>
										Running Security Analysis...
									</Typography>
									<Typography
										variant="body2"
										sx={{ color: "rgba(255,255,255,0.7)" }}
									>
										This may take a few moments
									</Typography>
								</Box>
							)}

							{!scanningSecurity && (
								<SecurityFindings scanResults={securityScanResults} />
							)}
						</GlassPaper>
					</>
				) : (
					<Typography
						sx={{ textAlign: "center", color: "rgba(255,255,255,0.7)" }}
					>
						Please upload an APK first to view statistics.
					</Typography>
				);

			case 2:
				return (
					<>
						<Typography variant="h5" sx={{ mb: 3, color: "#00e676" }}>
							App Icons
						</Typography>
						<Grid container spacing={3}>
							{icons.map((icon, index) => (
								<Grid item xs={12} sm={6} md={4} key={index}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
										}}
									>
										<CardMedia
											component="img"
											image={`${API_URL}/uploads${icon}`}
											alt="icon"
											sx={{
												height: 100,
												objectFit: "contain",
												p: 2,
											}}
										/>
										<CardContent>
											<Typography
												sx={{ color: "#fff", wordBreak: "break-all" }}
											>
												{icon.split("/").pop()}
											</Typography>
										</CardContent>
										<CardActions sx={{ p: 2, pt: 0, flexWrap: "wrap", gap: 1 }}>
											<input
												type="file"
												accept="image/*"
												onChange={handleLogoChange}
												style={{ color: "#fff" }}
											/>
											<NeonButton
												size="small"
												onClick={() => replaceLogo(icon)}
											>
												Replace
											</NeonButton>
										</CardActions>
									</Card>
								</Grid>
							))}
						</Grid>

						<Typography variant="h5" sx={{ mt: 4, mb: 3, color: "#00e676" }}>
							App Assets
						</Typography>
						<Grid container spacing={3}>
							{assets.map((asset, index) => (
								<Grid item xs={12} sm={6} md={4} key={index}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
										}}
									>
										<CardMedia
											component="img"
											image={`${API_URL}/uploads${asset}`}
											alt="asset"
											sx={{
												height: 100,
												objectFit: "contain",
												p: 2,
											}}
										/>
										<CardContent>
											<Typography
												sx={{ color: "#fff", wordBreak: "break-all" }}
											>
												{asset.split("/").pop()}
											</Typography>
										</CardContent>
										<CardActions sx={{ p: 2, pt: 0, flexWrap: "wrap", gap: 1 }}>
											<input
												type="file"
												accept="image/*"
												onChange={handleAssetChange}
												style={{ color: "#fff" }}
											/>
											<NeonButton
												size="small"
												onClick={() => replaceAsset(asset)}
											>
												Replace
											</NeonButton>
										</CardActions>
									</Card>
								</Grid>
							))}
						</Grid>

						<GlassPaper sx={{ p: 3, mt: 4 }}>
							<Typography variant="h5" sx={{ mb: 2, color: "#00e676" }}>
								Permissions
							</Typography>
							<Grid container spacing={2}>
								{permissions.map((perm, index) => (
									<Grid item xs={12} sm={6} key={index}>
										<FormControlLabel
											control={
												<Switch
													checked={perm.enabled}
													onChange={() => togglePermission(perm.name)}
													sx={{
														"& .MuiSwitch-switchBase.Mui-checked": {
															color: "#00e676",
														},
													}}
												/>
											}
											label={perm.name}
											sx={{
												color: "#fff",
											}}
										/>
									</Grid>
								))}
							</Grid>
						</GlassPaper>

						<GlassPaper sx={{ p: 3, mt: 4 }}>
							<Typography variant="h5" sx={{ mb: 2, color: "#00e676" }}>
								Listeners
							</Typography>
							{listeners.map((listener, index) => (
								<Box key={index} sx={{ mb: 2 }}>
									<TextField
										fullWidth
										label={`Listener ${index + 1}`}
										value={listener}
										onChange={(e) => updateListeners(index, e.target.value)}
										sx={{
											background: "rgba(255, 255, 255, 0.2)",
											borderRadius: "4px",
											"& .MuiInputBase-root": {
												color: "#fff",
											},
										}}
									/>
								</Box>
							))}
							<Button
								variant="contained"
								onClick={addListener}
								sx={{
									backgroundColor: "#00e676",
									"&:hover": {
										backgroundColor: "#00c4b4",
									},
								}}
							>
								Add Listener
							</Button>
						</GlassPaper>
					</>
				);

			case 3:
				return (
					<GlassPaper sx={{ p: 3, mb: 4 }}>
						<Typography variant="h5" sx={{ mb: 3, color: "#00e676" }}>
							Rebuild APK
						</Typography>
						<Typography
							variant="body1"
							sx={{ mb: 3, color: "rgba(255,255,255,0.8)" }}
						>
							Review your modifications and rebuild the APK with your changes.
						</Typography>

						<Divider sx={{ my: 4, borderColor: "rgba(0, 230, 118, 0.3)" }} />

						<Grid container spacing={2}>
							<Grid item xs={12} sm={6}>
								<NeonButton
									fullWidth
									variant="contained"
									onClick={saveManifest}
									sx={{
										background: "#00e676",
										"&:hover": {
											backgroundColor: "#00c4b4",
										},
									}}
								>
									Save Manifest
								</NeonButton>
							</Grid>
							<Grid item xs={12} sm={6}>
								<NeonButton
									fullWidth
									variant="contained"
									onClick={() => {
										saveManifest();
										rebuildApk();
									}}
									sx={{
										background: "#00e676",
										"&:hover": {
											backgroundColor: "#00c4b4",
										},
									}}
								>
									Rebuild & Download
								</NeonButton>
							</Grid>
						</Grid>
					</GlassPaper>
				);

			case 4:
				return (
					<GlassPaper sx={{ p: 4, mb: 4, textAlign: "center" }}>
						<CheckCircleIcon sx={{ fontSize: 80, color: "#00e676", mb: 2 }} />
						<Typography
							variant="h4"
							sx={{
								mb: 2,
								color: "#00e676",
								fontWeight: "bold",
							}}
						>
							Modification Complete!
						</Typography>
						<Typography
							variant="body1"
							sx={{ mb: 4, color: "rgba(255,255,255,0.8)" }}
						>
							Your modified APK has been downloaded successfully.
						</Typography>

						<Button
							variant="contained"
							onClick={handleReset}
							startIcon={<CloudUploadIcon />}
							sx={{
								background: "linear-gradient(45deg, #00e676, #00c4b4)",
								"&:hover": {
									background: "linear-gradient(45deg, #00c4b4, #00e676)",
								},
								mr: 2,
							}}
						>
							Process Another APK
						</Button>

						{activeStep > 0 && (
							<Button
								onClick={handleBack}
								sx={{ color: "rgba(255,255,255,0.7)" }}
							>
								Back
							</Button>
						)}
					</GlassPaper>
				);

			default:
				return null;
		}
	};

	return (
		<ThemeProvider theme={theme}>
			<Container
				sx={{
					py: 5,
					minHeight: "100vh",
					maxWidth: "100vw",
					background: isDarkMode
						? "linear-gradient(135deg, #1a237e 0%, #120136 100%)"
						: "linear-gradient(135deg, #e8eaf6 0%, #c5cae9 100%)",
					color: isDarkMode ? "#fff" : "#1a237e",
					transition: "background 0.3s ease",
				}}
			>
				{/* Header with Theme Toggle */}
				<Box
					sx={{
						display: "flex",
						justifyContent: "space-between",
						alignItems: "center",
						mb: 4,
						flexWrap: "wrap",
						gap: 2,
					}}
				>
					<Typography
						variant="h3"
						sx={{
							fontWeight: 900,
							background: "linear-gradient(45deg, #00e676, #00c4b4)",
							WebkitBackgroundClip: "text",
							WebkitTextFillColor: "transparent",
							textShadow: "0 0 20px rgba(0, 230, 118, 0.5)",
							letterSpacing: "2px",
							textAlign: "center",
						}}
					>
						AReversy
					</Typography>

					<Tooltip
						title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
					>
						<IconButton
							onClick={toggleTheme}
							sx={{
								color: "#00e676",
								"&:hover": {
									background: "rgba(0, 230, 118, 0.1)",
								},
							}}
						>
							{isDarkMode ? <LightModeIcon /> : <DarkModeIcon />}
						</IconButton>
					</Tooltip>
				</Box>

				{/* Progress Stepper */}
				{processingStep >= 0 && (
					<GlassPaper sx={{ p: 3, mb: 4 }}>
						<Typography variant="h6" sx={{ mb: 2, color: "#00e676" }}>
							Processing...
						</Typography>
						<Box sx={{ mb: 4 }}>
							<Box
								sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}
							>
								{processingSteps.map((step, index) => (
									<Typography
										key={index}
										variant="caption"
										sx={{
											color:
												index <= processingStep
													? "#00e676"
													: "rgba(255, 255, 255, 0.5)",
											fontWeight: index === processingStep ? "bold" : "normal",
											fontSize: index === processingStep ? "14px" : "12px",
										}}
									>
										{step}
									</Typography>
								))}
							</Box>
							<LinearProgress
								variant="determinate"
								value={(processingStep / (processingSteps.length - 1)) * 100}
								sx={{
									height: 8,
									borderRadius: 4,
									backgroundColor: "rgba(255, 255, 255, 0.1)",
									"& .MuiLinearProgress-bar": {
										background: "linear-gradient(45deg, #00e676, #00c4b4)",
										borderRadius: 4,
									},
								}}
							/>
						</Box>
					</GlassPaper>
				)}

				{/* Wizard Stepper */}
				{!loading && (
					<GlassPaper sx={{ p: 3, mb: 4 }}>
						<WizardStepper activeStep={activeStep} completed={completed} />
					</GlassPaper>
				)}

				{loading && (
					<LoadingOverlay>
						<Fade in={loading}>
							<Box sx={{ textAlign: "center" }}>
								<CircularProgress size={60} sx={{ color: "#00e676", mb: 2 }} />
								<Typography variant="h6" sx={{ color: "#fff" }}>
									Processing APK...
								</Typography>
								<Typography
									variant="body2"
									sx={{ color: "rgba(255,255,255,0.7)" }}
								>
									This may take a few minutes
								</Typography>
							</Box>
						</Fade>
					</LoadingOverlay>
				)}

				{/* Toast Notification */}
				<Toast
					open={toast.open}
					message={toast.message}
					severity={toast.severity}
					onClose={handleToastClose}
				/>

				{/* Step Content */}
				{renderStepContent(activeStep)}

				{/* Navigation Buttons */}
				{activeStep < 4 && (
					<Box sx={{ display: "flex", justifyContent: "space-between", mt: 4 }}>
						<Button
							disabled={activeStep === 0}
							onClick={handleBack}
							sx={{
								color: "rgba(255,255,255,0.7)",
								"&.Mui-disabled": {
									color: "rgba(255,255,255,0.3)",
								},
							}}
						>
							Back
						</Button>

						{activeStep === 0 && (
							<Button
								variant="contained"
								onClick={handleNext}
								disabled={!file || !completed[0]}
								sx={{
									background: "linear-gradient(45deg, #00e676, #00c4b4)",
									"&:hover": {
										background: "linear-gradient(45deg, #00c4b4, #00e676)",
									},
								}}
							>
								Skip to Analysis
							</Button>
						)}

						{activeStep === 1 && (
							<Button
								variant="contained"
								onClick={handleNext}
								sx={{
									background: "linear-gradient(45deg, #00e676, #00c4b4)",
									"&:hover": {
										background: "linear-gradient(45deg, #00c4b4, #00e676)",
									},
								}}
							>
								Proceed to Modify
							</Button>
						)}

						{activeStep === 2 && (
							<Button
								variant="contained"
								onClick={handleNext}
								sx={{
									background: "linear-gradient(45deg, #00e676, #00c4b4)",
									"&:hover": {
										background: "linear-gradient(45deg, #00c4b4, #00e676)",
									},
								}}
							>
								Proceed to Rebuild
							</Button>
						)}

						{activeStep === 3 && (
							<Button
								variant="contained"
								onClick={handleNext}
								sx={{
									background: "linear-gradient(45deg, #00e676, #00c4b4)",
									"&:hover": {
										background: "linear-gradient(45deg, #00c4b4, #00e676)",
									},
								}}
							>
								Complete
							</Button>
						)}
					</Box>
				)}
			</Container>
		</ThemeProvider>
	);
}

export default App;
