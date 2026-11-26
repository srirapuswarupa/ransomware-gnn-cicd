"""
Graph Neural Network Architectures for API Call Graph Malware Classification.
Implements GCN (Amer et al., GraphShield), GAT (Veličković et al., Lin et al.),
and GraphSAGE (Hamilton et al., Bilot et al.) in pure vectorized PyTorch.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple

class GCNLayer(nn.Module):
    """
    Graph Convolutional Network (GCN) layer with symmetric degree normalization.
    H' = D_inv_sqrt * (A + I) * D_inv_sqrt * H * W
    """
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.linear = nn.Linear(in_features, out_features, bias=False)
        self.bias = nn.Parameter(torch.zeros(out_features))
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.linear.weight)
        nn.init.zeros_(self.bias)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_weight: Optional[torch.Tensor] = None) -> torch.Tensor:
        num_nodes = x.size(0)
        
        # Add self-loops
        loop_index = torch.arange(0, num_nodes, dtype=torch.long, device=x.device)
        loop_index = loop_index.unsqueeze(0).repeat(2, 1)
        full_edge_index = torch.cat([edge_index, loop_index], dim=1)
        
        src, dst = full_edge_index[0], full_edge_index[1]
        
        # Compute node degrees
        deg = torch.zeros(num_nodes, device=x.device)
        deg.scatter_add_(0, dst, torch.ones_like(dst, dtype=torch.float32))
        deg_inv_sqrt = deg.pow(-0.5)
        deg_inv_sqrt[torch.isinf(deg_inv_sqrt)] = 0.0
        
        # Symmetric normalization coefficient
        norm = deg_inv_sqrt[src] * deg_inv_sqrt[dst]
        
        # Message passing: Linear transformation followed by scatter aggregation
        h = self.linear(x)
        msg = h[src] * norm.unsqueeze(-1)
        
        out = torch.zeros_like(h)
        out.scatter_add_(0, dst.unsqueeze(-1).expand_as(msg), msg)
        out = out + self.bias
        return out

class GATLayer(nn.Module):
    """
    Graph Attention Network (GAT) layer with multi-head self-attention.
    Computes dynamic attention coefficients between interacting API nodes.
    """
    def __init__(self, in_features: int, out_features: int, heads: int = 4, concat: bool = True, dropout: float = 0.1):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.heads = heads
        self.concat = concat
        self.dropout = dropout

        self.lin = nn.Linear(in_features, heads * out_features, bias=False)
        self.att_src = nn.Parameter(torch.zeros(1, heads, out_features))
        self.att_dst = nn.Parameter(torch.zeros(1, heads, out_features))
        self.leaky_relu = nn.LeakyReLU(0.2)
        
        if not concat:
            self.bias = nn.Parameter(torch.zeros(out_features))
        else:
            self.bias = nn.Parameter(torch.zeros(heads * out_features))
            
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.lin.weight)
        nn.init.xavier_uniform_(self.att_src)
        nn.init.xavier_uniform_(self.att_dst)
        nn.init.zeros_(self.bias)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_weight: Optional[torch.Tensor] = None) -> torch.Tensor:
        num_nodes = x.size(0)
        
        # Add self-loops
        loop_index = torch.arange(0, num_nodes, dtype=torch.long, device=x.device).unsqueeze(0).repeat(2, 1)
        full_edge_index = torch.cat([edge_index, loop_index], dim=1)
        src, dst = full_edge_index[0], full_edge_index[1]

        # [N, heads, out_features]
        h = self.lin(x).view(-1, self.heads, self.out_features)
        
        # Attention scores: alpha_ij = LeakyReLU(a_src * h_i + a_dst * h_j)
        alpha_src = (h * self.att_src).sum(dim=-1) # [N, heads]
        alpha_dst = (h * self.att_dst).sum(dim=-1) # [N, heads]
        edge_alpha = self.leaky_relu(alpha_src[src] + alpha_dst[dst]) # [E, heads]
        
        # Softmax over incoming neighbors per head
        # Use exp and scatter_add
        edge_alpha_exp = torch.exp(edge_alpha - edge_alpha.max())
        head_denom = torch.zeros(num_nodes, self.heads, device=x.device)
        head_denom.scatter_add_(0, dst.unsqueeze(-1).expand_as(edge_alpha_exp), edge_alpha_exp)
        head_denom = head_denom + 1e-12
        alpha_norm = edge_alpha_exp / head_denom[dst]
        alpha_norm = F.dropout(alpha_norm, p=self.dropout, training=self.training)
        
        if edge_weight is not None:
            # Scale attention by edge feature weight if provided
            edge_weight_expanded = edge_weight.unsqueeze(-1)
            alpha_norm = alpha_norm * edge_weight_expanded[:alpha_norm.size(0)]

        # Weighted message aggregation
        msg = h[src] * alpha_norm.unsqueeze(-1) # [E, heads, out_features]
        out = torch.zeros(num_nodes, self.heads, self.out_features, device=x.device)
        dst_expanded = dst.view(-1, 1, 1).expand_as(msg)
        out.scatter_add_(0, dst_expanded, msg)

        if self.concat:
            out = out.view(-1, self.heads * self.out_features)
        else:
            out = out.mean(dim=1)
            
        out = out + self.bias
        return out

class GraphSAGELayer(nn.Module):
    """
    GraphSAGE (Sample and Aggregate) layer with mean aggregation.
    h_v = sigma( W_self * h_v + W_neigh * Mean_{u in N(v)} h_u )
    """
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.lin_self = nn.Linear(in_features, out_features)
        self.lin_neigh = nn.Linear(in_features, out_features, bias=False)
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.lin_self.weight)
        nn.init.zeros_(self.lin_self.bias)
        nn.init.xavier_uniform_(self.lin_neigh.weight)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, edge_weight: Optional[torch.Tensor] = None) -> torch.Tensor:
        num_nodes = x.size(0)
        src, dst = edge_index[0], edge_index[1]
        
        # Mean neighbor aggregation
        deg = torch.zeros(num_nodes, device=x.device)
        deg.scatter_add_(0, dst, torch.ones_like(dst, dtype=torch.float32))
        deg = torch.clamp(deg, min=1.0)
        
        msg = x[src]
        neigh_sum = torch.zeros_like(x)
        neigh_sum.scatter_add_(0, dst.unsqueeze(-1).expand_as(msg), msg)
        neigh_mean = neigh_sum / deg.unsqueeze(-1)
        
        out = self.lin_self(x) + self.lin_neigh(neigh_mean)
        return out

class GNNClassifier(nn.Module):
    """
    Full Graph Neural Network Model for Graph-Level Ransomware Classification.
    Supports GCN, GAT, and GraphSAGE backbones with dual pooling (Mean + Max).
    Outputs class logits: [0: Benign, 1: Suspicious, 2: Ransomware].
    """
    def __init__(
        self,
        in_dim: int = 14,
        hidden_dim: int = 64,
        num_classes: int = 3,
        gnn_type: str = "gat",
        num_layers: int = 2,
        dropout: float = 0.2
    ):
        super().__init__()
        self.gnn_type = gnn_type.lower()
        self.hidden_dim = hidden_dim
        self.dropout = dropout

        # API Feature projection
        self.input_proj = nn.Linear(in_dim, hidden_dim)

        # Message Passing Layers
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()

        for i in range(num_layers):
            in_f = hidden_dim
            out_f = hidden_dim
            
            if self.gnn_type == "gcn":
                conv = GCNLayer(in_f, out_f)
            elif self.gnn_type == "gat":
                # 4 heads for intermediate, 1 head for final or concat
                heads = 4 if i < num_layers - 1 else 2
                conv = GATLayer(in_f, out_f // heads, heads=heads, concat=True, dropout=dropout)
            elif self.gnn_type == "graphsage":
                conv = GraphSAGELayer(in_f, out_f)
            else:
                raise ValueError(f"Unsupported GNN type: {gnn_type}")
                
            self.convs.append(conv)
            self.norms.append(nn.LayerNorm(hidden_dim))

        # Classification Head: Combined Mean and Max global pooling -> 2 * hidden_dim
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
        edge_weight: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Returns:
            logits: [B, num_classes]
            node_embeddings: [N, hidden_dim]
        """
        num_nodes = x.size(0)
        if batch is None:
            # Single graph inference
            batch = torch.zeros(num_nodes, dtype=torch.long, device=x.device)

        h = F.relu(self.input_proj(x))
        h = F.dropout(h, p=self.dropout, training=self.training)

        for conv, norm in zip(self.convs, self.norms):
            h_residual = h
            h = conv(h, edge_index, edge_weight)
            h = norm(h)
            h = F.relu(h) + h_residual
            h = F.dropout(h, p=self.dropout, training=self.training)

        # Global Graph Pooling (Mean + Max Pooling across all nodes of the graph)
        num_graphs = int(batch.max().item()) + 1 if num_nodes > 0 else 1
        
        # Mean pooling
        mean_pool = torch.zeros(num_graphs, self.hidden_dim, device=x.device)
        counts = torch.zeros(num_graphs, 1, device=x.device)
        counts.scatter_add_(0, batch.unsqueeze(-1), torch.ones_like(batch.unsqueeze(-1), dtype=torch.float32))
        counts = torch.clamp(counts, min=1.0)
        mean_pool.scatter_add_(0, batch.unsqueeze(-1).expand_as(h), h)
        mean_pool = mean_pool / counts

        # Max pooling
        max_pool = torch.full((num_graphs, self.hidden_dim), -1e9, device=x.device)
        for g_idx in range(num_graphs):
            mask = (batch == g_idx)
            if mask.any():
                max_pool[g_idx] = h[mask].max(dim=0).values
            else:
                max_pool[g_idx] = 0.0

        graph_emb = torch.cat([mean_pool, max_pool], dim=-1)
        logits = self.classifier(graph_emb)
        return logits, h
