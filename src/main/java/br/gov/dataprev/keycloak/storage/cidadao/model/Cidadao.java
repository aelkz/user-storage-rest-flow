
package br.gov.dataprev.keycloak.storage.cidadao.model;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import br.gov.dataprev.keycloak.storage.rest.model.Entity;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "cidadao", propOrder = { "cpf" })
@JsonIgnoreProperties(ignoreUnknown=true)
public class Cidadao implements Entity, UserModel {
    
    private Long cpf;

    private String nome;
    private String email;
    private String senha;
    private String telefone;
    private boolean isPrimeiroLogin;

    public Long getCpf() {
        return cpf;
    }

    public void setCpf(Long cpf) {
        this.cpf = cpf;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    public String getTelefone() {
        return telefone;
    }

    public void setTelefone(String telefone) {
        this.telefone = telefone;
    }
    
    public boolean isPrimeiroLogin() {
    	return this.isPrimeiroLogin;
    }
    
    public void setPrimeiroLogin(boolean isPrimeiroLogin) {
    	this.isPrimeiroLogin = isPrimeiroLogin;
    }
    
    @Override
    public String toString() {
    	return "{"
    			+ "\"cpf\":" + getCpf()
    			+ "\"senha\":" + getSenha()
    			+ "\"nome\":" + getNome()
    			+ "\"email\":" + getEmail()
    			+ "\"telefone\":" + getTelefone()
    			+ "\"isPrimeiroLogin\":" + isPrimeiroLogin()
    			+ "}";
    }

    
	@Override
	public void deleteRoleMapping(RoleModel arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Set<RoleModel> getClientRoleMappings(ClientModel arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<RoleModel> getRealmRoleMappings() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<RoleModel> getRoleMappings() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void grantRole(RoleModel arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean hasRole(RoleModel arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void addRequiredAction(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void addRequiredAction(RequiredAction arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public List<String> getAttribute(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<String, List<String>> getAttributes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Long getCreatedTimestamp() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getFederationLink() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getFirstAttribute(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getFirstName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<GroupModel> getGroups() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getId() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getLastName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<String> getRequiredActions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getServiceAccountClientLink() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isEmailVerified() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isMemberOf(GroupModel arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void joinGroup(GroupModel arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void leaveGroup(GroupModel arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeAttribute(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeRequiredAction(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeRequiredAction(RequiredAction arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setAttribute(String arg0, List<String> arg1) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setCreatedTimestamp(Long arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEmailVerified(boolean arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEnabled(boolean arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setFederationLink(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setFirstName(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setLastName(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setServiceAccountClientLink(String arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setSingleAttribute(String arg0, String arg1) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setUsername(String arg0) {
		// TODO Auto-generated method stub
		
	}
}
