import React, { useState } from "react";
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
} from "@mui/material";
import { styled } from "@mui/material/styles";
import { Bar, Pie } from "react-chartjs-2";
import {
	Chart as ChartJS,
	ArcElement,
	BarElement,
	CategoryScale,
	LinearScale,
	Tooltip,
	Legend,
} from "chart.js";
import "./styles/App.css";

// Register Chart.js components
ChartJS.register(
	ArcElement,
	BarElement,
	CategoryScale,
	LinearScale,
	Tooltip,
	Legend
);

// Custom styled components
const GlassPaper = styled(Paper)(() => ({
	background: "rgba(255, 255, 255, 0.05)",
	backdropFilter: "blur(10px)",
	border: "1px solid rgba(255, 255, 255, 0.1)",
	boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
	borderRadius: "12px",
}));

const NeonButton = styled(Button)(() => ({
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

const LoadingOverlay = styled(Box)(() => ({
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

function App() {
	const API_URL = "http://localhost:5000";
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

	const handleFileChange = (e) => setFile(e.target.files[0]);
	const handleLogoChange = (e) => setNewLogo(e.target.files[0]);
	const handleAssetChange = (e) => setNewAsset(e.target.files[0]);

	const replaceLogo = async (icon) => {
		if (!newLogo) {
			alert("Please select a logo to replace with");
			return;
		}

		const formData = new FormData();
		formData.append("logo", newLogo);
		formData.append("iconPath", icon);

		try {
			const res = await axios.post(`${API_URL}/replace-logo`, formData);
			alert(res.data.message);
		} catch (err) {
			alert(
				"Error replacing logo: " + (err.response?.data?.error || err.message)
			);
		}
	};

	const replaceAsset = async (asset) => {
		if (!newAsset) {
			alert("Please select an asset to replace with");
			return;
		}

		const formData = new FormData();
		formData.append("asset", newAsset);
		formData.append("assetPath", asset);

		try {
			const res = await axios.post(`${API_URL}/replace-asset`, formData);
			alert(res.data.message);
		} catch (err) {
			alert(
				"Error replacing asset: " + (err.response?.data?.error || err.message)
			);
		}
	};

	const togglePermission = (permName) => {
		setPermissions(
			permissions.map((p) =>
				p.name === permName ? { ...p, enabled: !p.enabled } : p
			)
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
		try {
			const res = await axios.post(`${API_URL}/save-manifest`, {
				dir: decompiledDir,
				permissions: permissions.filter((p) => p.enabled).map((p) => p.name),
				listeners,
			});
			alert(res.data.message);
		} catch (err) {
			alert(
				"Error saving manifest: " + (err.response?.data?.error || err.message)
			);
		}
	};

	const rebuildApk = async () => {
		try {
			const res = await axios.post(
				`${API_URL}/rebuild`,
				{
					dir: decompiledDir,
				},
				{
					responseType: "blob",
				}
			);

			// Create a download link for the APK
			const url = window.URL.createObjectURL(new Blob([res.data]));
			const link = document.createElement("a");
			link.href = url;
			link.setAttribute("download", "modified.apk");
			document.body.appendChild(link);
			link.click();
			link.remove();
		} catch (err) {
			alert("Error rebuilding APK: " + err.message);
		}
	};

	const uploadApk = async () => {
		if (!file) {
			alert("Please upload an APK first");
			return;
		}
		setLoading(true); // Show loading overlay
		const formData = new FormData();
		formData.append("apk", file);
		try {
			const res = await axios.post(`${API_URL}/upload`, formData, {
				timeout: 10000000,
			});
			setDecompiledDir(res.data.decompiled_dir);
			setIcons(res.data.icons);
			setAssets(res.data.assets);
			setPermissions(
				res.data.permissions.map((perm) => ({ name: perm, enabled: true }))
			);
			setListeners(res.data.listeners);
			setStats(res.data.stats); // Set stats from response
			alert(res.data.message);
		} catch (err) {
			alert(
				"Error uploading APK: " + (err.response?.data?.error || err.message)
			);
		} finally {
			setLoading(false); // Hide loading overlay
		}
	};

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

	return (
		<Container
			sx={{
				py: 5,
				minHeight: "100vh",
				maxWidth: "100vw",
				background: "linear-gradient(135deg, #1a237e 0%, #120136 100%)",
				color: "#fff",
			}}
		>
			<Typography
				variant="h3"
				gutterBottom
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

			{/* APK Upload Section */}
			<GlassPaper sx={{ p: 3, mb: 4 }}>
				<Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
					<input
						type="file"
						accept=".apk"
						onChange={handleFileChange}
						style={{ color: "#fff" }}
					/>
					<NeonButton variant="contained" onClick={uploadApk}>
						Upload APK
					</NeonButton>
				</Box>
			</GlassPaper>

			{loading && (
				<LoadingOverlay>
					<CircularProgress size={50} color="primary" />
				</LoadingOverlay>
			)}

			{decompiledDir && (
				<>
					{stats && (
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
							<Grid container spacing={3} sx={{ textAlign: "center" }}>
								{/* Lines of Code */}
								<Grid item xs={12} sm={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Lines of Code
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.lines_of_code}
											</Typography>
										</CardContent>
									</Card>
								</Grid>

								{/* Permissions */}
								<Grid item xs={12} sm={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Permissions
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.total_permissions}
											</Typography>
										</CardContent>
									</Card>
								</Grid>

								{/* Listeners */}
								<Grid item xs={12} sm={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Listeners
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.total_listeners}
											</Typography>
										</CardContent>
									</Card>
								</Grid>
							</Grid>

							<Grid container spacing={3} sx={{ mt: 3, textAlign: "center" }}>
								{/* Activities */}
								<Grid item xs={12} sm={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Activities
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.total_activities}
											</Typography>
										</CardContent>
									</Card>
								</Grid>

								{/* Background Workers */}
								<Grid item xs={12} sm={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Background Workers
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.background_workers}
											</Typography>
										</CardContent>
									</Card>
								</Grid>

								{/* Classes */}
								<Grid item xs={12} sm={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Classes
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.total_classes}
											</Typography>
										</CardContent>
									</Card>
								</Grid>
							</Grid>

							<Divider sx={{ my: 4, borderColor: "rgba(0, 230, 118, 0.3)" }} />

							<Grid container spacing={3} sx={{ textAlign: "center" }}>
								{/* Icons */}
								<Grid item xs={12} sm={6} md={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Icons
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.total_icons}
											</Typography>
										</CardContent>
									</Card>
								</Grid>

								{/* Assets */}
								<Grid item xs={12} sm={6} md={4}>
									<Card
										sx={{
											background: "rgba(255, 255, 255, 0.03)",
											border: "1px solid rgba(255, 255, 255, 0.1)",
											boxShadow: "0 8px 32px 0 rgba(31, 38, 135, 0.37)",
											borderRadius: "12px",
											padding: "16px",
											textAlign: "center",
										}}
									>
										<CardContent>
											<Typography
												variant="h6"
												sx={{
													color: "#00e676",
													fontWeight: "bold",
												}}
											>
												Assets
											</Typography>
											<Typography
												variant="h4"
												sx={{
													color: "#fff",
													fontWeight: "bold",
													letterSpacing: "2px",
												}}
											>
												{stats.total_assets}
											</Typography>
										</CardContent>
									</Card>
								</Grid>
							</Grid>
						</GlassPaper>
					)}

					<Divider
						sx={{
							my: 4,
							borderColor: "rgba(0, 230, 118, 0.3)",
							boxShadow: "0 0 10px rgba(0, 230, 118, 0.2)",
						}}
					/>

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
										<Typography sx={{ color: "#fff", wordBreak: "break-all" }}>
											{icon.split("/").pop()}
										</Typography>
									</CardContent>
									<CardActions sx={{ p: 2, pt: 0 }}>
										<input
											type="file"
											accept="image/*"
											onChange={handleLogoChange}
											style={{ color: "#fff" }}
										/>
										<NeonButton size="small" onClick={() => replaceLogo(icon)}>
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
										<Typography sx={{ color: "#fff", wordBreak: "break-all" }}>
											{asset.split("/").pop()}
										</Typography>
									</CardContent>
									<CardActions sx={{ p: 2, pt: 0 }}>
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

					<Divider sx={{ my: 4, borderColor: "rgba(0, 230, 118, 0.3)" }} />
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
					<NeonButton
						fullWidth
						variant="contained"
						onClick={rebuildApk}
						sx={{
							background: "#00e676",
							"&:hover": {
								backgroundColor: "#00c4b4",
							},
							mt: 2,
						}}
					>
						Rebuild APK
					</NeonButton>
				</>
			)}
		</Container>
	);
}

export default App;
