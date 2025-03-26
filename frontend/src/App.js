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
	Grid,
	Paper,
	Divider,
	Card,
	CardMedia,
	CardContent,
	CardActions,
} from "@mui/material";
import { styled } from "@mui/material/styles";
import "./styles/App.css";

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

function App() {
	const [file, setFile] = useState(null);
	const [decompiledDir, setDecompiledDir] = useState("");
	const [icons, setIcons] = useState([]);
	const [assets, setAssets] = useState([]);
	const [permissions, setPermissions] = useState([]);
	const [listeners, setListeners] = useState([]);
	const [newLogo, setNewLogo] = useState(null);
	const [newAsset, setNewAsset] = useState(null);

	// Handle APK upload
	const handleFileChange = (e) => setFile(e.target.files[0]);

	const uploadApk = async () => {
		const formData = new FormData();
		formData.append("apk", file);
		try {
			const res = await axios.post("http://localhost:5000/upload", formData);
			setDecompiledDir(res.data.decompiled_dir);
			setIcons(res.data.icons);
			setAssets(res.data.assets);
			setPermissions(
				res.data.permissions.map((perm) => ({ name: perm, enabled: true }))
			);
			setListeners(res.data.listeners);
			alert(res.data.message);
		} catch (err) {
			alert(
				"Error uploading APK: " + (err.response?.data?.error || err.message)
			);
		}
	};

	// Replace logo
	const handleLogoChange = (e) => setNewLogo(e.target.files[0]);

	const replaceLogo = async (oldLogo) => {
		if (!newLogo) return alert("Please select a new logo");
		const formData = new FormData();
		formData.append("logo", newLogo);
		formData.append("decompiled_dir", decompiledDir);
		formData.append("old_logo", oldLogo);
		try {
			const res = await axios.post(
				"http://localhost:5000/replace_logo",
				formData
			);
			alert(res.data.message);
			setNewLogo(null);
		} catch (err) {
			alert(
				"Error replacing logo: " + (err.response?.data?.error || err.message)
			);
		}
	};

	// Replace asset
	const handleAssetChange = (e) => setNewAsset(e.target.files[0]);

	const replaceAsset = async (oldAsset) => {
		if (!newAsset) return alert("Please select a new asset");
		const formData = new FormData();
		formData.append("asset", newAsset);
		formData.append("decompiled_dir", decompiledDir);
		formData.append("old_asset", oldAsset);
		try {
			const res = await axios.post(
				"http://localhost:5000/replace_asset",
				formData
			);
			alert(res.data.message);
			setNewAsset(null);
		} catch (err) {
			alert(
				"Error replacing asset: " + (err.response?.data?.error || err.message)
			);
		}
	};

	// Modify permissions
	const togglePermission = (permName) => {
		setPermissions(
			permissions.map((p) =>
				p.name === permName ? { ...p, enabled: !p.enabled } : p
			)
		);
	};

	// Modify listeners
	const updateListeners = (index, value) => {
		const newListeners = [...listeners];
		newListeners[index] = value;
		setListeners(newListeners);
	};

	const addListener = () => setListeners([...listeners, ""]);

	const saveManifest = async () => {
		try {
			const enabledPermissions = permissions
				.filter((p) => p.enabled)
				.map((p) => p.name);
			await axios.post("http://localhost:5000/modify_manifest", {
				decompiled_dir: decompiledDir,
				permissions: enabledPermissions,
				listeners,
			});
			alert("Manifest updated");
		} catch (err) {
			alert(
				"Error updating manifest: " + (err.response?.data?.error || err.message)
			);
		}
	};

	// Rebuild APK
	const rebuildApk = async () => {
		try {
			const res = await axios.post(
				"http://localhost:5000/rebuild",
				{
					decompiled_dir: decompiledDir,
				},
				{ responseType: "blob" }
			);
			const url = window.URL.createObjectURL(new Blob([res.data]));
			const link = document.createElement("a");
			link.href = url;
			link.setAttribute("download", "modified.apk");
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
		} catch (err) {
			alert(
				"Error rebuilding APK: " + (err.response?.data?.error || err.message)
			);
		}
	};

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

			{decompiledDir && (
				<>
					<Divider
						sx={{
							my: 4,
							borderColor: "rgba(0, 230, 118, 0.3)",
							boxShadow: "0 0 10px rgba(0, 230, 118, 0.2)",
						}}
					/>

					{/* Icons Section */}
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
										image={`http://localhost:5000/uploads${icon}`}
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

					{/* Assets Section */}
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
										image={`http://localhost:5000/uploads${asset}`}
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

					{/* Permissions Section */}
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
													"& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track":
														{
															backgroundColor: "#00e676",
														},
												}}
											/>
										}
										label={perm.name}
										sx={{ color: "#fff" }}
									/>
								</Grid>
							))}
						</Grid>
					</GlassPaper>

					{/* Listeners Section */}
					<GlassPaper sx={{ p: 3, mt: 4 }}>
						<Typography variant="h5" sx={{ mb: 2, color: "#00e676" }}>
							Listeners
						</Typography>
						{listeners.map((listener, index) => (
							<TextField
								key={index}
								value={listener}
								onChange={(e) => updateListeners(index, e.target.value)}
								label={`Listener ${index + 1}`}
								variant="outlined"
								sx={{
									mb: 2,
									"& .MuiOutlinedInput-root": {
										color: "#fff",
										"& fieldset": { borderColor: "rgba(0, 230, 118, 0.3)" },
										"&:hover fieldset": { borderColor: "#00e676" },
									},
									"& .MuiInputLabel-root": {
										color: "rgba(255, 255, 255, 0.7)",
									},
								}}
								fullWidth
							/>
						))}
						<NeonButton variant="outlined" onClick={addListener}>
							Add Listener
						</NeonButton>
					</GlassPaper>

					{/* Action Buttons */}
					<Box
						sx={{ mt: 4, display: "flex", gap: 2, justifyContent: "center" }}
					>
						<NeonButton onClick={saveManifest}>Save Manifest</NeonButton>
						<NeonButton onClick={rebuildApk}>Download Modified APK</NeonButton>
					</Box>
				</>
			)}
		</Container>
	);
}

export default App;
