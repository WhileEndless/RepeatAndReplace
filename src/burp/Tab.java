package burp;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import java.awt.*;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class Tab implements ITab {
    JTabbedPane mainTabbedPane;
    IBurpExtenderCallbacks callbacks;
    JPanel errorPanel, tokenObtainPanel, replacePanel, previewPanel;
    private ITextEditor requestEditor;
    private ITextEditor responseEditor;
    private ArrayList<JTabbedPane> tabs = new ArrayList<>();
    private String[] trigerConditionEmbed = {"Request Header", "Request Body", "Response Header", "Reponse Body", "Request","Reponse"};
    JPanel basepanel;
    public DefaultTableModel model;
    private JTable table;
    public JButton reloadButton;
    public Tab(IBurpExtenderCallbacks callbacks) {
    	
    	this.callbacks=callbacks;
    	
    	this.basepanel = new JPanel();
    	basepanel.setLayout(new BorderLayout());
    	model = new DefaultTableModel() {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            }
        };

    	model.addColumn("Active");
    	model.addColumn("Name");
    	model.addColumn("Path");
    	table = new JTable(model) {
            @Override
            public boolean isCellEditable(int row, int column) {
            	if(column==0) {return true;}
                return false;
            }
        };

    	JButton addButton = new JButton("Add");
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    model.addRow(new Object[]{true, selectedFile.getName(), selectedFile.getPath()});
                }
            }
        });
        
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    model.removeRow(selectedRow);
                }
            }
        });
        JButton upButton = new JButton("Up");
        upButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow > 0) {
                    swapRows(selectedRow, selectedRow - 1);
                    table.setRowSelectionInterval(selectedRow - 1, selectedRow - 1);
                }
            }
        });
        this.reloadButton = new JButton("Reload");
       
        
        JButton downButton = new JButton("Down");
                
        basepanel.add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(upButton);
        buttonPanel.add(downButton);
        buttonPanel.add(reloadButton);
        basepanel.add(buttonPanel, BorderLayout.SOUTH);
    }
    private void swapRows(int row1, int row2) {
        for (int i = 0; i < model.getColumnCount(); i++) {
            Object temp = model.getValueAt(row1, i);
            model.setValueAt(model.getValueAt(row2, i), row1, i);
            model.setValueAt(temp, row2, i);
        }
    }

    @Override
    public String getTabCaption() {
        return "Repet And Replace";
    }

    @Override
    public Component getUiComponent() {
        return basepanel;
    }
}
