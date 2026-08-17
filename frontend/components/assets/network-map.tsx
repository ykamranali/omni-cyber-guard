"use client";

import { useRef, useMemo, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Text, Line, Sphere, Html } from "@react-three/drei";
import * as THREE from "three";

interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  risk_score: number;
}

interface NetworkMapProps {
  assets: Asset[];
}

function AssetNode({ asset, position, onClick }: { asset: Asset; position: [number, number, number], onClick: (a: Asset) => void }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);

  // Rotate slightly for visual effect
  useFrame((state, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.5;
      meshRef.current.rotation.x += delta * 0.2;
    }
  });

  const color = asset.risk_score > 70 ? "#ef4444" : asset.risk_score > 30 ? "#f59e0b" : "#10b981";

  return (
    <group position={position}>
      <mesh
        ref={meshRef}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
        onClick={() => onClick(asset)}
      >
        <icosahedronGeometry args={[0.5, 1]} />
        <meshStandardMaterial color={color} wireframe={hovered} />
      </mesh>
      
      {/* Label */}
      <Html position={[0, -0.8, 0]} center className="pointer-events-none">
        <div className="flex flex-col items-center bg-surface/80 backdrop-blur px-2 py-1 rounded border border-border text-xs text-ink whitespace-nowrap">
          <span className="font-semibold">{asset.hostname}</span>
          <span className="text-muted text-[10px]">{asset.ip_address}</span>
        </div>
      </Html>
    </group>
  );
}

function CoreRouter() {
  const meshRef = useRef<THREE.Mesh>(null);
  
  useFrame((state, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y -= delta * 0.2;
    }
  });

  return (
    <group position={[0, 0, 0]}>
      <mesh ref={meshRef}>
        <boxGeometry args={[1.5, 0.5, 1.5]} />
        <meshStandardMaterial color="#3b82f6" roughness={0.2} metalness={0.8} />
      </mesh>
      <Html position={[0, -0.8, 0]} center className="pointer-events-none">
        <div className="bg-primary text-white text-xs px-2 py-1 rounded shadow-lg whitespace-nowrap">
          Core Network
        </div>
      </Html>
    </group>
  );
}

export function NetworkMap({ assets }: NetworkMapProps) {
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  // Distribute assets in a circle around the core
  const nodes = useMemo(() => {
    const radius = Math.max(4, assets.length * 0.8);
    return assets.map((asset, index) => {
      const angle = (index / assets.length) * Math.PI * 2;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      // add slight random height variation
      const y = (Math.random() - 0.5) * 2;
      return { asset, position: [x, y, z] as [number, number, number] };
    });
  }, [assets]);

  return (
    <div className="relative h-full w-full rounded-xl overflow-hidden bg-[#0f172a]">
      <Canvas camera={{ position: [0, 8, 12], fov: 45 }}>
        <ambientLight intensity={0.5} />
        <pointLight position={[10, 10, 10]} intensity={1} />
        <pointLight position={[-10, -10, -10]} intensity={0.5} color="#3b82f6" />
        
        <CoreRouter />
        
        {nodes.map((node) => (
          <group key={node.asset.id}>
            <Line
              points={[[0, 0, 0], node.position]}
              color="#334155"
              lineWidth={1}
              transparent
              opacity={0.5}
            />
            <AssetNode 
              asset={node.asset} 
              position={node.position} 
              onClick={setSelectedAsset} 
            />
          </group>
        ))}
        
        <OrbitControls 
          enablePan={true}
          enableZoom={true}
          enableRotate={true}
          autoRotate={true}
          autoRotateSpeed={0.5}
          maxDistance={30}
          minDistance={5}
        />
      </Canvas>

      {/* Selected Asset Overlay */}
      {selectedAsset && (
        <div className="absolute top-4 right-4 w-64 bg-surface/90 backdrop-blur-md border border-border rounded-lg p-4 shadow-xl text-sm z-10 animate-in fade-in zoom-in-95">
          <div className="flex justify-between items-center mb-2 border-b border-border pb-2">
            <h3 className="font-bold text-ink">Asset Details</h3>
            <button onClick={() => setSelectedAsset(null)} className="text-muted hover:text-ink">&times;</button>
          </div>
          <div className="space-y-1">
            <p><span className="text-muted">Hostname:</span> {selectedAsset.hostname}</p>
            <p><span className="text-muted">IP:</span> {selectedAsset.ip_address}</p>
            <p><span className="text-muted">Risk Score:</span> <span className={selectedAsset.risk_score > 70 ? 'text-red-500' : selectedAsset.risk_score > 30 ? 'text-yellow-500' : 'text-green-500 font-bold'}>{selectedAsset.risk_score}</span></p>
          </div>
        </div>
      )}
    </div>
  );
}
